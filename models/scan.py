from database import db, iso, utcnow

# Lifecycle: Waiting -> Initializing -> Crawling -> Testing -> AI Analysis -> Completed
#            (or Failed / Cancelled at any point)
ACTIVE_STATUSES = ("Waiting", "Initializing", "Crawling", "Testing", "AI Analysis")
FINAL_STATUSES = ("Completed", "Failed", "Cancelled")


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target_url = db.Column(db.String(2048), nullable=False)
    scan_status = db.Column(db.String(20), nullable=False, default="Waiting", index=True)
    scan_type = db.Column(db.String(20), nullable=False, default="standard")
    options = db.Column(db.Text, default="{}")            # JSON: extra seed paths, etc.
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    scan_start_time = db.Column(db.DateTime)
    scan_end_time = db.Column(db.DateTime)
    pages_discovered = db.Column(db.Integer, default=0, nullable=False)
    tests_completed = db.Column(db.Integer, default=0, nullable=False)
    total_findings = db.Column(db.Integer, default=0, nullable=False)
    risk_score = db.Column(db.Float, default=0.0, nullable=False)
    risk_level = db.Column(db.String(20), default="None", nullable=False)
    progress = db.Column(db.Integer, default=0, nullable=False)
    current_activity = db.Column(db.String(500), default="Queued")
    error_message = db.Column(db.String(1000))

    owner = db.relationship("User", back_populates="scans")
    vulnerabilities = db.relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan",
                                      order_by="Vulnerability.priority")
    logs = db.relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan",
                           order_by="ScanLog.id", lazy="dynamic")
    reports = db.relationship("Report", back_populates="scan", cascade="all, delete-orphan")

    @property
    def is_active(self) -> bool:
        return self.scan_status in ACTIVE_STATUSES

    @property
    def duration_seconds(self):
        if self.scan_start_time and self.scan_end_time:
            return int((self.scan_end_time - self.scan_start_time).total_seconds())
        return None

    def severity_counts(self) -> dict:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for v in self.vulnerabilities:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts

    def progress_payload(self) -> dict:
        return {
            "scan_id": self.id,
            "status": self.scan_status,
            "progress": self.progress,
            "activity": self.current_activity,
            "pages": self.pages_discovered,
            "tests": self.tests_completed,
            "findings": self.total_findings,
            "error": self.error_message,
        }

    def to_dict(self) -> dict:
        d = self.progress_payload()
        d.update({
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "created_at": iso(self.created_at),
            "start_time": iso(self.scan_start_time),
            "end_time": iso(self.scan_end_time),
            "duration": self.duration_seconds,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "severity": self.severity_counts(),
        })
        return d


class ScanLog(db.Model):
    __tablename__ = "scan_logs"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    log_message = db.Column(db.String(1000), nullable=False)
    status = db.Column(db.String(20), default="info")     # info | success | warning | error
    timestamp = db.Column(db.DateTime, default=utcnow, nullable=False)

    scan = db.relationship("Scan", back_populates="logs")

    def to_dict(self) -> dict:
        return {"id": self.id, "message": self.log_message, "status": self.status, "timestamp": iso(self.timestamp)}
