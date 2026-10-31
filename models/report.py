from database import db, iso, utcnow


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    report_type = db.Column(db.String(10), nullable=False)    # pdf | html
    file_path = db.Column(db.String(500), nullable=False)
    generated_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    scan = db.relationship("Scan", back_populates="reports")

    def to_dict(self) -> dict:
        return {"id": self.id, "scan_id": self.scan_id, "type": self.report_type, "generated_at": iso(self.generated_at)}
