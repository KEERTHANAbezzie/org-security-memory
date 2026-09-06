from __future__ import annotations
from datetime import datetime
from typing import Optional
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, Table, Column, Index, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase): pass

incident_assets = Table("incident_assets", Base.metadata,
    Column("incident_id", ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("asset_id", ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True))
incident_users = Table("incident_users", Base.metadata,
    Column("incident_id", ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("user_id", String(120), primary_key=True))
incident_techniques = Table("incident_techniques", Base.metadata,
    Column("incident_id", ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("technique_id", String(80), primary_key=True))
rule_techniques = Table("rule_techniques", Base.metadata,
    Column("rule_id", ForeignKey("detection_rules.id", ondelete="CASCADE"), primary_key=True),
    Column("technique_id", String(80), primary_key=True))
rule_assets = Table("rule_assets", Base.metadata,
    Column("rule_id", ForeignKey("detection_rules.id", ondelete="CASCADE"), primary_key=True),
    Column("asset_id", ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True))

class Incident(Base):
    __tablename__="incidents"
    id: Mapped[str]=mapped_column(String(40),primary_key=True)
    timestamp: Mapped[datetime]=mapped_column(DateTime,index=True,nullable=False)
    severity: Mapped[str]=mapped_column(String(20),index=True,nullable=False)
    category: Mapped[str]=mapped_column(String(80),index=True,nullable=False)
    title: Mapped[str]=mapped_column(String(200),nullable=False)
    description: Mapped[str]=mapped_column(Text,nullable=False)
    root_cause: Mapped[Optional[str]]=mapped_column(Text)
    remediation: Mapped[Optional[str]]=mapped_column(Text)
    outcome: Mapped[Optional[str]]=mapped_column(Text)
    family_id: Mapped[Optional[str]]=mapped_column(String(80),index=True)
    embedding_text: Mapped[Optional[str]]=mapped_column(Text)
    alerts: Mapped[list["Alert"]]=relationship(back_populates="incident")
    tickets: Mapped[list["Ticket"]]=relationship(back_populates="incident")
    changes: Mapped[list["Change"]]=relationship(back_populates="incident")
    remediations: Mapped[list["Remediation"]]=relationship(back_populates="incident")
    assets: Mapped[list["Asset"]]=relationship(secondary=incident_assets,back_populates="incidents")
    evidence: Mapped[list["Evidence"]]=relationship(back_populates="incident")
    __table_args__=(Index("ix_incidents_family_timestamp","family_id","timestamp"),)

class Alert(Base):
    __tablename__="alerts"
    id: Mapped[str]=mapped_column(String(40),primary_key=True)
    timestamp: Mapped[datetime]=mapped_column(DateTime,index=True,nullable=False)
    source: Mapped[str]=mapped_column(String(80),nullable=False)
    rule_id: Mapped[Optional[str]]=mapped_column(ForeignKey("detection_rules.id"))
    severity: Mapped[str]=mapped_column(String(20),nullable=False)
    status: Mapped[str]=mapped_column(String(30),nullable=False)
    incident_id: Mapped[Optional[str]]=mapped_column(ForeignKey("incidents.id"))
    true_positive: Mapped[Optional[bool]]=mapped_column(Boolean)
    false_positive: Mapped[Optional[bool]]=mapped_column(Boolean)
    incident: Mapped[Optional["Incident"]]=relationship(back_populates="alerts")
    rule: Mapped[Optional["DetectionRule"]]=relationship(back_populates="alerts")

class Ticket(Base):
    __tablename__="tickets"
    id: Mapped[str]=mapped_column(String(40),primary_key=True)
    timestamp: Mapped[datetime]=mapped_column(DateTime,index=True,nullable=False)
    title: Mapped[str]=mapped_column(String(200),nullable=False)
    description: Mapped[str]=mapped_column(Text,nullable=False)
    comments: Mapped[str]=mapped_column(Text,nullable=False)
    owner: Mapped[str]=mapped_column(String(120),nullable=False)
    status: Mapped[str]=mapped_column(String(30),nullable=False)
    resolution: Mapped[Optional[str]]=mapped_column(Text)
    incident_id: Mapped[Optional[str]]=mapped_column(ForeignKey("incidents.id"))
    incident: Mapped[Optional["Incident"]]=relationship(back_populates="tickets")

class Change(Base):
    __tablename__="changes"
    id: Mapped[str]=mapped_column(String(40),primary_key=True)
    timestamp: Mapped[datetime]=mapped_column(DateTime,index=True,nullable=False)
    change_type: Mapped[str]=mapped_column(String(40),nullable=False)
    actor: Mapped[str]=mapped_column(String(120),nullable=False)
    service: Mapped[str]=mapped_column(String(120),nullable=False)
    asset_id: Mapped[Optional[str]]=mapped_column(ForeignKey("assets.id"))
    summary: Mapped[str]=mapped_column(Text,nullable=False)
    diff: Mapped[Optional[str]]=mapped_column(Text)
    incident_id: Mapped[Optional[str]]=mapped_column(ForeignKey("incidents.id"))
    asset: Mapped[Optional["Asset"]]=relationship(back_populates="changes")
    incident: Mapped[Optional["Incident"]]=relationship(back_populates="changes")

class Asset(Base):
    __tablename__="assets"
    id: Mapped[str]=mapped_column(String(40),primary_key=True)
    name: Mapped[str]=mapped_column(String(160),nullable=False)
    asset_type: Mapped[str]=mapped_column(String(50),nullable=False)
    owner: Mapped[str]=mapped_column(String(120),nullable=False)
    environment: Mapped[str]=mapped_column(String(30),nullable=False)
    criticality: Mapped[str]=mapped_column(String(20),nullable=False)
    telemetry_sources: Mapped[list]=mapped_column(JSON,nullable=False,default=list)
    monitoring_status: Mapped[str]=mapped_column(String(30),nullable=False)
    incidents: Mapped[list["Incident"]]=relationship(secondary=incident_assets,back_populates="assets")
    changes: Mapped[list["Change"]]=relationship(back_populates="asset")
    rules: Mapped[list["DetectionRule"]]=relationship(secondary=rule_assets,back_populates="assets")

class DetectionRule(Base):
    __tablename__="detection_rules"
    id: Mapped[str]=mapped_column(String(40),primary_key=True)
    name: Mapped[str]=mapped_column(String(180),nullable=False)
    logic: Mapped[str]=mapped_column(Text,nullable=False)
    telemetry_requirements: Mapped[list]=mapped_column(JSON,nullable=False,default=list)
    alert_volume: Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    true_positive_count: Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    false_positive_count: Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    effectiveness: Mapped[Optional[float]]=mapped_column(Float)
    enabled: Mapped[bool]=mapped_column(Boolean,nullable=False,default=True)
    alerts: Mapped[list["Alert"]]=relationship(back_populates="rule")
    assets: Mapped[list["Asset"]]=relationship(secondary=rule_assets,back_populates="rules")

class Remediation(Base):
    __tablename__="remediations"
    id: Mapped[str]=mapped_column(String(40),primary_key=True)
    incident_id: Mapped[str]=mapped_column(ForeignKey("incidents.id"),nullable=False)
    family_id: Mapped[Optional[str]]=mapped_column(String(80),index=True)
    action: Mapped[str]=mapped_column(Text,nullable=False)
    timestamp: Mapped[datetime]=mapped_column(DateTime,index=True,nullable=False)
    owner: Mapped[str]=mapped_column(String(120),nullable=False)
    target: Mapped[str]=mapped_column(String(180),nullable=False)
    rationale: Mapped[str]=mapped_column(Text,nullable=False)
    result: Mapped[str]=mapped_column(Text,nullable=False)
    recurrence_after_days: Mapped[Optional[int]]=mapped_column(Integer)
    effectiveness_label: Mapped[Optional[str]]=mapped_column(String(30))
    incident: Mapped["Incident"]=relationship(back_populates="remediations")

class Runbook(Base):
    __tablename__="runbooks"
    id: Mapped[str]=mapped_column(String(40),primary_key=True)
    name: Mapped[str]=mapped_column(String(180),nullable=False)
    scope: Mapped[str]=mapped_column(Text,nullable=False)
    version: Mapped[str]=mapped_column(String(30),nullable=False)
    owner: Mapped[str]=mapped_column(String(120),nullable=False)
    last_validated: Mapped[datetime]=mapped_column(DateTime,nullable=False)

class Evidence(Base):
    __tablename__="evidence"
    id: Mapped[str]=mapped_column(String(40),primary_key=True)
    source_type: Mapped[str]=mapped_column(String(40),nullable=False)
    source_id: Mapped[str]=mapped_column(String(80),nullable=False)
    timestamp: Mapped[datetime]=mapped_column(DateTime,index=True,nullable=False)
    content: Mapped[str]=mapped_column(Text,nullable=False)
    confidence: Mapped[float]=mapped_column(Float,nullable=False,default=1.0)
    provenance: Mapped[dict]=mapped_column(JSON,nullable=False,default=dict)
    incident_id: Mapped[Optional[str]]=mapped_column(ForeignKey("incidents.id"))
    incident: Mapped[Optional["Incident"]]=relationship(back_populates="evidence")
