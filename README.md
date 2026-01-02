# Leave Enterprise Backend v11 (Updated)

## Required environment variables
- `DATABASE_URL` - PostgreSQL connection string
- `JWT_SECRET` - REQUIRED (no default)

## Recommended environment variables
- `NODE_ENV=production`
- `ALLOWED_ORIGINS=https://your-frontend-domain.com,https://another.com`
- `JWT_EXPIRES_IN=2h`
- `LOGIN_RATE_LIMIT_MAX=20` (per 15 minutes)
- `BODY_LIMIT=1mb`
- `AUTO_BACKUP=true|false`

## New / Updated features
- Reports filters: `department_id`, `emp_no`, `status`, `unregistered`
- Daily report pagination: `limit`, `offset`
- Export CSV (daily only): `GET /api/reports/export?type=daily&format=csv&date=YYYY-MM-DD...`
- Export XLSX (daily/monthly/yearly/trends): `GET /api/reports/export?type=daily|monthly|yearly|trends&format=xlsx...`
- Planned vs Actual minutes returned in reports
- Security hardening: helmet, restricted CORS in production, login rate limiting

## Run
```bash
npm install
npm start
```

## DB schema
See `schema.sql` (includes performance indexes).
