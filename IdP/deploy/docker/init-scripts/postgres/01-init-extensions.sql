-- PostgreSQL Initialization Script
-- Creates required extensions and base configuration

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Verify uuidv7 is available (PostgreSQL 17+)
-- If not available, create a fallback function
DO $$
BEGIN
    -- Test if uuidv7() exists
    PERFORM uuidv7();
EXCEPTION
    WHEN undefined_function THEN
        -- Create a fallback uuidv7 function using uuid-ossp
        -- Note: This is a simplified version, not a true UUIDv7
        CREATE OR REPLACE FUNCTION uuidv7() RETURNS uuid AS $func$
        DECLARE
            unix_ts_ms bytea;
            uuid_bytes bytea;
        BEGIN
            unix_ts_ms := substring(int8send((extract(epoch from clock_timestamp()) * 1000)::bigint) from 3);
            uuid_bytes := unix_ts_ms || gen_random_bytes(10);
            -- Set version (7) and variant bits
            uuid_bytes := set_byte(uuid_bytes, 6, (get_byte(uuid_bytes, 6) & 15) | 112);  -- version 7
            uuid_bytes := set_byte(uuid_bytes, 8, (get_byte(uuid_bytes, 8) & 63) | 128); -- variant 2
            RETURN encode(uuid_bytes, 'hex')::uuid;
        END;
        $func$ LANGUAGE plpgsql VOLATILE;
        
        RAISE NOTICE 'Created fallback uuidv7() function';
END;
$$;

-- Create function to auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Verify setup
DO $$
BEGIN
    RAISE NOTICE 'PostgreSQL initialization complete';
    RAISE NOTICE 'Testing uuidv7(): %', uuidv7();
END;
$$;
