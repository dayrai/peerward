-- Wire 4 retains canonical endpoint-list constraints while adding QUIC.
-- Preserve all historical migrations and the existing function identity.
CREATE OR REPLACE FUNCTION public.peerward_valid_network_endpoint(endpoint text) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE STRICT
    SET search_path = pg_catalog, public, pg_temp
    AS $_$
DECLARE
    authority text;
    host text;
    port_text text;
    label text;
    parsed_port integer;
BEGIN
    IF endpoint ~ '^tcp://[^/?#@]+$' THEN
        authority := substring(endpoint FROM 7);
    ELSIF endpoint ~ '^quic://[^/?#@]+$' THEN
        authority := substring(endpoint FROM 8);
    ELSIF endpoint ~ '^wss://[^/?#@]+/peerward$' THEN
        authority := substring(endpoint FROM 7 FOR length(endpoint) - 15);
    ELSE
        RETURN false;
    END IF;
    IF left(authority, 1) = '[' THEN
        IF authority !~ '^\[[0-9a-f:.]+\]:[0-9]+$' THEN
            RETURN false;
        END IF;
        host := split_part(authority, ']:', 1);
        host := substring(host FROM 2);
        port_text := split_part(authority, ']:', 2);
        IF family(host::inet) <> 6 OR pg_catalog.host(host::inet) <> host
           OR host::inet = '::'::inet OR host::inet <<= 'ff00::/8'::inet THEN
            RETURN false;
        END IF;
    ELSE
        host := regexp_replace(authority, ':[^:]+$', '');
        port_text := substring(authority FROM ':([^:]+)$');
        IF host = authority OR host = '' OR host <> lower(host) THEN
            RETURN false;
        END IF;
        BEGIN
            IF family(host::inet) <> 4 OR pg_catalog.host(host::inet) <> host
               OR host::inet = '0.0.0.0'::inet OR host::inet <<= '224.0.0.0/4'::inet THEN
                RETURN false;
            END IF;
        EXCEPTION WHEN invalid_text_representation THEN
            IF length(host) > 253 OR host ~ '^[0-9.]+$' THEN
                RETURN false;
            END IF;
            FOREACH label IN ARRAY string_to_array(host, '.') LOOP
                IF label = '' OR length(label) > 63
                   OR label !~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$' THEN
                    RETURN false;
                END IF;
            END LOOP;
        END;
    END IF;
    parsed_port := port_text::integer;
    RETURN parsed_port BETWEEN 1 AND 65535 AND port_text = parsed_port::text;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RETURN false;
END
$_$;

