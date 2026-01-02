-- Basic schema for short leave v9 (simplified)

CREATE TABLE IF NOT EXISTS departments(
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY,
  emp_no TEXT,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL, -- EMPLOYEE, HOD, HR, ADMIN, SECURITY
  department_id INTEGER REFERENCES departments(id),
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS leaves(
  id SERIAL PRIMARY KEY,
  leave_code TEXT UNIQUE,
  employee_id INTEGER REFERENCES users(id),
  department_id INTEGER REFERENCES departments(id),

  -- request type flags
  is_hod_request BOOLEAN NOT NULL DEFAULT FALSE,
  is_unregistered BOOLEAN NOT NULL DEFAULT FALSE,

  -- unregistered info (when is_unregistered=TRUE)
  unregistered_emp_id TEXT,
  unregistered_name TEXT,
  unregistered_department TEXT,

  date DATE NOT NULL,
  planned_out TIME NOT NULL,
  planned_in TIME NOT NULL,
  actual_out TIME,
  actual_in TIME,

  note TEXT,
  created_by_role TEXT,

  status TEXT NOT NULL, -- PENDING_HOD, PENDING_ADMIN, PENDING_HR, FINAL_APPROVED, FINAL_REJECTED, REJECTED_HOD, REJECTED_ADMIN, APPEAL_PENDING_HR, AUTO_CLOSED

  -- appeals
  appeal_used BOOLEAN NOT NULL DEFAULT FALSE,
  appeal_note TEXT,
  appealed_by_role TEXT,
  appealed_at TIMESTAMP,

  -- HR decision metadata (when PENDING_HR)
  hr_decision TEXT,
  hr_decided_by INTEGER REFERENCES users(id),
  hr_decided_at TIMESTAMP,

  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS notifications(
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT,
  link TEXT,
  meta JSONB,
  is_read BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs(
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  role TEXT,
  action TEXT NOT NULL,
  entity TEXT,
  entity_id INTEGER,
  ip TEXT,
  user_agent TEXT,
  meta JSONB,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_leaves_date ON leaves(date);
CREATE INDEX IF NOT EXISTS idx_leaves_status ON leaves(status);
CREATE INDEX IF NOT EXISTS idx_leaves_dept_date ON leaves(department_id, date);
CREATE INDEX IF NOT EXISTS idx_leaves_employee_date ON leaves(employee_id, date);
CREATE INDEX IF NOT EXISTS idx_users_emp_no ON users(emp_no);
-- Performance indexes (reports/filtering)
CREATE INDEX IF NOT EXISTS idx_leaves_date ON leaves(date);
CREATE INDEX IF NOT EXISTS idx_leaves_status ON leaves(status);
CREATE INDEX IF NOT EXISTS idx_leaves_dept_date ON leaves(department_id, date);
CREATE INDEX IF NOT EXISTS idx_leaves_emp_date ON leaves(employee_id, date);
CREATE INDEX IF NOT EXISTS idx_users_emp_no ON users(emp_no);

-- Enforce allowed status transitions at DB level (prevents unauthorized direct DB updates)
CREATE OR REPLACE FUNCTION enforce_leave_status_transition()
RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status NOT IN ('PENDING_HOD','PENDING_ADMIN','PENDING_HR') THEN
      RAISE EXCEPTION 'Invalid initial status %', NEW.status;
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.status = OLD.status THEN
    RETURN NEW;
  END IF;

  IF OLD.status = 'PENDING_HOD' AND NEW.status IN ('FINAL_APPROVED','REJECTED_HOD') THEN
    RETURN NEW;
  ELSIF OLD.status = 'PENDING_ADMIN' AND NEW.status IN ('FINAL_APPROVED','REJECTED_ADMIN') THEN
    RETURN NEW;
  ELSIF OLD.status = 'PENDING_HR' AND NEW.status IN ('FINAL_APPROVED','FINAL_REJECTED') THEN
    RETURN NEW;
  ELSIF OLD.status IN ('REJECTED_HOD','REJECTED_ADMIN') AND NEW.status = 'APPEAL_PENDING_HR' THEN
    RETURN NEW;
  ELSIF OLD.status = 'APPEAL_PENDING_HR' AND NEW.status IN ('FINAL_APPROVED','FINAL_REJECTED') THEN
    RETURN NEW;
  ELSIF OLD.status = 'FINAL_APPROVED' AND NEW.status = 'AUTO_CLOSED' THEN
    RETURN NEW;
  ELSE
    RAISE EXCEPTION 'Invalid status transition from % to %', OLD.status, NEW.status;
  END IF;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_enforce_leave_status_transition ON leaves;
CREATE TRIGGER trg_enforce_leave_status_transition
BEFORE INSERT OR UPDATE OF status ON leaves
FOR EACH ROW EXECUTE FUNCTION enforce_leave_status_transition();
CREATE TABLE IF NOT EXISTS security_logs(
  id SERIAL PRIMARY KEY,
  leave_id INTEGER REFERENCES leaves(id) ON DELETE CASCADE,
  leave_code TEXT,
  action TEXT NOT NULL CHECK (action IN ('OUT','IN')),
  marked_at TIMESTAMP NOT NULL DEFAULT NOW(),
  marked_by INTEGER REFERENCES users(id),
  note TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_leaves_leave_code ON leaves(leave_code) WHERE leave_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_logs_leave_id ON security_logs(leave_id);
CREATE INDEX IF NOT EXISTS idx_security_logs_leave_code ON security_logs(leave_code);
