from dataclasses import dataclass,field

@dataclass
class EmailData:
    """
    Typed wrapper around the parser output.
    Passed into every detector - never mutated.
    """

    id: str
    subject: str
    from_: str
    to: str
    date: str
    reply_to: str
    body_text: str
    body_html: str
    links: list[str]
    attachments: list[dict]
    headers: dict

    @staticmethod
    def from_dict(d:dict) -> "EmailData":
        return EmailData(
            id=d["id"],           subject=d["subject"],
            from_=d["from"],      to=d["to"],
            date=d["date"],       reply_to=d["reply_to"],
            body_text=d["body_text"], body_html=d["body_html"],
            links=d["links"],     attachments=d["attachments"],
            headers=d["headers"],
        )
    

@dataclass
class DetectionSignal:
    """
    Ouput of a single detector.
    score: 0.0(safe) - 1.0(definite phishing)
    flags: human-readable reasons
    """

    name: str
    score: float
    flags: list[str] = field(default_factory=list)

@dataclass
class ScanResult:
    """
    Final aggregated output of the fulll scan pipeline.
    """

    email_id: str
    subject: str
    from_: str
    final_score: float
    is_phishing: bool
    signals: list[DetectionSignal]

    @property
    def all_flags(self) -> list[str]:
        return [f for signal in self.signals for f in signal.flags]

