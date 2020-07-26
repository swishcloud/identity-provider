ALTER TABLE public."user" ADD COLUMN failure_num integer;
UPDATE public."user" SET failure_num = 0;
ALTER TABLE public."user" ALTER COLUMN failure_num SET NOT NULL;