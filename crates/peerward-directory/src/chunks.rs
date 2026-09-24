/// Independently bounded piece of one serialized signed object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionChunk {
    /// Owning mesh.
    pub mesh_id: MeshId,
    /// Object revision.
    pub revision: u64,
    /// Zero-based index.
    pub index: u32,
    /// Fixed count for the assembly.
    pub count: u32,
    /// Piece bytes.
    pub body: Vec<u8>,
}

/// Splits bytes into nonempty independently bounded chunks.
pub fn split_chunks(
    mesh_id: MeshId,
    revision: u64,
    bytes: &[u8],
    maximum_body: usize,
) -> Result<Vec<RevisionChunk>, DirectoryError> {
    if maximum_body == 0 || bytes.is_empty() {
        return Err(DirectoryError::MixedChunks);
    }
    let count = bytes.len().div_ceil(maximum_body);
    let count = u32::try_from(count).map_err(|_| DirectoryError::MixedChunks)?;
    bytes
        .chunks(maximum_body)
        .enumerate()
        .map(|(index, body)| {
            Ok(RevisionChunk {
                mesh_id,
                revision,
                index: u32::try_from(index).map_err(|_| DirectoryError::MixedChunks)?,
                count,
                body: body.to_vec(),
            })
        })
        .collect()
}

/// Stateful all-or-nothing chunk collector with rollback protection.
#[derive(Debug)]
pub struct ChunkAssembler {
    mesh_id: MeshId,
    accepted_revision: Option<u64>,
    pending: Option<PendingChunks>,
    maximum_chunks: u32,
    maximum_bytes: usize,
}

#[derive(Debug)]
struct PendingChunks {
    revision: u64,
    count: u32,
    bytes: usize,
    parts: BTreeMap<u32, Vec<u8>>,
}

impl ChunkAssembler {
    /// Creates a bounded assembler for one mesh.
    pub fn new(mesh_id: MeshId, maximum_chunks: u32, maximum_bytes: usize) -> Self {
        Self {
            mesh_id,
            accepted_revision: None,
            pending: None,
            maximum_chunks,
            maximum_bytes,
        }
    }

    /// Last revision explicitly committed by the caller.
    pub const fn accepted_revision(&self) -> Option<u64> {
        self.accepted_revision
    }

    /// Receives state from redundant Relay streams without reinstalling old revisions.
    /// Already committed revisions and identical in-flight chunks are discarded;
    /// conflicting chunks and wrong-Mesh input still fail strict validation.
    pub fn push_redundant(&mut self, chunk: RevisionChunk) -> Result<Option<Vec<u8>>, DirectoryError> {
        if chunk.mesh_id != self.mesh_id {
            return Err(DirectoryError::WrongMesh);
        }
        if self.accepted_revision.is_some_and(|revision| chunk.revision <= revision) {
            return Ok(None);
        }
        if self.pending.as_ref().is_some_and(|pending| {
            pending.revision == chunk.revision
                && pending.count == chunk.count
                && pending.parts.get(&chunk.index) == Some(&chunk.body)
        }) {
            return Ok(None);
        }
        self.push(chunk)
    }

    /// Adds one chunk, yielding bytes only when the exact set is complete.
    pub fn push(&mut self, chunk: RevisionChunk) -> Result<Option<Vec<u8>>, DirectoryError> {
        if chunk.mesh_id != self.mesh_id {
            return Err(DirectoryError::WrongMesh);
        }
        if self
            .accepted_revision
            .is_some_and(|value| chunk.revision <= value)
        {
            return Err(DirectoryError::Rollback);
        }
        if chunk.count == 0
            || chunk.count > self.maximum_chunks
            || chunk.index >= chunk.count
            || chunk.body.is_empty()
        {
            return Err(DirectoryError::MixedChunks);
        }
        if let Some(pending) = &self.pending
            && (pending.revision != chunk.revision || pending.count != chunk.count) {
                self.pending = None;
                return Err(DirectoryError::MixedChunks);
            }
        let pending = self.pending.get_or_insert_with(|| PendingChunks {
            revision: chunk.revision,
            count: chunk.count,
            bytes: 0,
            parts: BTreeMap::new(),
        });
        if pending.parts.contains_key(&chunk.index) {
            self.pending = None;
            return Err(DirectoryError::MixedChunks);
        }
        pending.bytes = pending
            .bytes
            .checked_add(chunk.body.len())
            .ok_or(DirectoryError::MixedChunks)?;
        if pending.bytes > self.maximum_bytes {
            self.pending = None;
            return Err(DirectoryError::MixedChunks);
        }
        pending.parts.insert(chunk.index, chunk.body);
        if pending.parts.len() != pending.count as usize {
            return Ok(None);
        }
        let completed = self.pending.take().expect("pending chunk set");
        let mut output = Vec::with_capacity(completed.bytes);
        for (_, part) in completed.parts {
            output.extend_from_slice(&part);
        }
        Ok(Some(output))
    }

    /// Commits a completely validated revision; failed validation leaves the old revision active.
    pub fn commit(&mut self, revision: u64) -> Result<(), DirectoryError> {
        if self
            .accepted_revision
            .is_some_and(|value| revision <= value)
        {
            return Err(DirectoryError::Rollback);
        }
        self.accepted_revision = Some(revision);
        Ok(())
    }
}
