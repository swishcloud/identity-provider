ALTER TABLE IF EXISTS public."user"
    ADD COLUMN IF NOT EXISTS role integer;
Update public."user" set role=1;
ALTER TABLE IF EXISTS public."user"
    ALTER COLUMN role SET NOT NULL;