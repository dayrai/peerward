/// A leased, fenced lifecycle operation. Requests never contain private keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshLifecycleJob {
    pub id: Uuid,
    pub mesh_id: MeshId,
    pub operation: String,
    pub request: Value,
    pub actor: String,
    pub status: String,
    pub stage: String,
    pub generation: i64,
    pub attempt: i32,
    pub consecutive_failures: i32,
    pub error_code: Option<String>,
}

fn lifecycle_job(row: &sqlx::postgres::PgRow) -> Result<MeshLifecycleJob, StoreError> {
    Ok(MeshLifecycleJob {
        id: row.try_get("id")?,
        mesh_id: MeshId::from_uuid(row.try_get("mesh_id")?).map_err(|_| StoreError::Invalid("mesh ID"))?,
        operation: row.try_get("operation")?, request: row.try_get("request")?,
        actor: row.try_get("actor")?, status: row.try_get("status")?, stage: row.try_get("stage")?,
        generation: row.try_get("generation")?, attempt: row.try_get("attempt")?,
        error_code: row.try_get("error_code")?,
        consecutive_failures: row.try_get("consecutive_failures")?,
    })
}

impl Store {
    /// Claim a bounded batch, reclaiming only expired leases. Every subsequent
    /// mutation must compare the returned generation within its transaction.
    pub async fn claim_mesh_jobs(&self, owner: Uuid, limit: u32) -> Result<Vec<MeshLifecycleJob>, StoreError> {
        let rows = sqlx::query(
            "WITH candidates AS (
               SELECT id FROM mesh_lifecycle_jobs
               WHERE status IN ('queued','running','waiting') AND next_attempt_at<=clock_timestamp()
                 AND (lease_until IS NULL OR lease_until<clock_timestamp())
               ORDER BY next_attempt_at,created_at FOR UPDATE SKIP LOCKED LIMIT $2
             ) UPDATE mesh_lifecycle_jobs j SET status='running',lease_owner=$1,
               lease_until=clock_timestamp()+interval '30 seconds',generation=generation+1,
               attempt=attempt+1,updated_at=clock_timestamp()
             FROM candidates c WHERE j.id=c.id RETURNING j.*")
            .bind(owner).bind(i64::from(limit.min(16))).fetch_all(self.pool()).await?;
        rows.iter().map(lifecycle_job).collect()
    }

    pub async fn mesh_job(&self, id: Uuid) -> Result<MeshLifecycleJob, StoreError> {
        let row = sqlx::query("SELECT * FROM mesh_lifecycle_jobs WHERE id=$1")
            .bind(id).fetch_optional(self.pool()).await?.ok_or(StoreError::NotFound)?;
        lifecycle_job(&row)
    }

    pub async fn mesh_jobs(&self, after: Option<PageCursor>, limit: u16) -> Result<Page<MeshLifecycleJob>, StoreError> {
        validate_limit(limit)?;
        let rows = sqlx::query("SELECT *,created_at AS cursor_time FROM mesh_lifecycle_jobs
            WHERE ($1::timestamptz IS NULL OR (created_at,id)<($1,$2))
            ORDER BY created_at DESC,id DESC LIMIT $3")
            .bind(after.map(|cursor| cursor.timestamp)).bind(after.map(|cursor| cursor.id))
            .bind(i64::from(limit)+1).fetch_all(self.pool()).await?;
        page_from_rows(rows, limit, |row| lifecycle_job(&row))
    }

    /// Release the lease after a small resumable step. A replaced worker cannot
    /// acknowledge another generation or revive a cancelled create operation.
    pub async fn finish_mesh_job_step(
        &self, job: &MeshLifecycleJob, owner: Uuid, stage: &str, status: &str, error: Option<&str>,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE mesh_lifecycle_jobs SET stage=$4,status=$5,error_code=$6,
             consecutive_failures=CASE WHEN $6::text IS NULL THEN 0 ELSE consecutive_failures+1 END,
             lease_owner=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()+interval '1 second',
             updated_at=clock_timestamp() WHERE id=$1 AND generation=$2 AND lease_owner=$3
             AND status='running' AND lease_until>clock_timestamp()")
            .bind(job.id).bind(job.generation).bind(owner).bind(stage).bind(status).bind(error)
            .execute(self.pool()).await?;
        if result.rows_affected() != 1 { return Err(StoreError::Conflict); }
        Ok(())
    }

    pub async fn retry_mesh_job(&self, id: Uuid, actor: &str) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE mesh_lifecycle_jobs j SET status='queued',error_code=NULL,consecutive_failures=0,next_attempt_at=clock_timestamp()
             WHERE j.id=$1 AND j.status='failed' AND (j.operation='delete' OR
               EXISTS(SELECT 1 FROM meshes m WHERE m.id=j.mesh_id AND m.lifecycle='creating'))")
            .bind(id).execute(&mut *transaction).await?;
        if result.rows_affected() != 1 { return Err(StoreError::Conflict); }
        append_audit(&mut transaction, None, actor, "mesh.lifecycle.retry", "mesh_lifecycle_job", Some(id), "success", json!({"job_id":id})).await?;
        transaction.commit().await?;
        Ok(())
    }
}
