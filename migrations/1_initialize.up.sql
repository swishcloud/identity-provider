-- Table: public."user"

-- DROP TABLE public."user";

CREATE TABLE public."user"
(
    id uuid NOT NULL,
    name character varying(10) COLLATE pg_catalog."default" NOT NULL,
    email text COLLATE pg_catalog."default",
    is_banned boolean,
    password text COLLATE pg_catalog."default",
    gender integer,
    email_confirmed boolean,
    email_activation_code text COLLATE pg_catalog."default",
    avatar text COLLATE pg_catalog."default",
    age integer,
    insert_time timestamp without time zone NOT NULL,
    update_time timestamp without time zone,
    CONSTRAINT user_pkey PRIMARY KEY (id),
    CONSTRAINT name_uniquekey UNIQUE (name),
    CONSTRAINT email_uniquekey UNIQUE (email)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;