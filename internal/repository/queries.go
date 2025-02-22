package repository

func upsertUserQuery(u User) (string, []any) {
	return `INSERT INTO users (email, given_name, family_name, picture_url) VALUES ($1, $2, $3, $4)
ON CONFLICT (email) DO UPDATE SET
	given_name = EXCLUDED.given_name,
	family_name = EXCLUDED.family_name,
	picture_url = EXCLUDED.picture_url`, []any{u.Email, u.GivenName, u.FamilyName, u.PictureURL}
}
