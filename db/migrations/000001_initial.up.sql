CREATE TABLE users (
   id SERIAL PRIMARY KEY,
   email VARCHAR(255) NOT NULL UNIQUE,
   given_name VARCHAR(100) NOT NULL,
   family_name VARCHAR(100) NOT NULL,
   picture_url VARCHAR(2048),
   created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
   updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION update_updated_at_column()
    RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();
