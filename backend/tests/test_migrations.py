import sqlite3
from pathlib import Path
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def config(url):
    base=Path(__file__).resolve().parents[1]
    result=Config(str(base/'alembic.ini'))
    result.set_main_option('script_location',str(base/'migrations'))
    result.set_main_option('sqlalchemy.url',url.replace('%','%%'))
    return result


def test_upgrade_existing_revision_one_preserves_data(tmp_path):
    path=tmp_path/'upgrade.db';url=f'sqlite:///{path}'
    cfg=config(url);command.upgrade(cfg,'0001')
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO users VALUES ('existing','existing.dev','existing@example.com','Existing User','hash','REQUESTER','Engineering',1,0,NULL,0,NULL,'2026-01-01 00:00:00')")
    command.upgrade(cfg,'head')
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT version_num FROM alembic_version').fetchone()[0]=='0005'
        assert db.execute('SELECT username FROM users').fetchone()[0]=='existing.dev'
        assert 'sessions_revocation_pending' in [r[1] for r in db.execute('PRAGMA table_info(users)')]
        assert 'entitlements' in [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    engine=create_engine(url)
    assert inspect(engine).get_foreign_keys('audit_exports')
    engine.dispose()


def test_postgres_migrations_and_workflow(monkeypatch):
    import os,uuid
    from sqlalchemy.engine import make_url
    from sqlalchemy import text
    import app.main as main
    from app.config import settings
    from app.models import get_db
    from app.models.database import read_snapshot
    from app.services import audit_service
    from sqlalchemy.orm import sessionmaker
    from fastapi.testclient import TestClient
    base_url=os.environ.get('TEST_POSTGRES_URL')
    if not base_url:pytest.skip('TEST_POSTGRES_URL is required for PostgreSQL integration')
    base=create_engine(base_url);schema='test_'+uuid.uuid4().hex
    with base.begin() as db:db.execute(text('CREATE SCHEMA '+schema))
    url=make_url(base_url).update_query_dict({'options':'-csearch_path='+schema}).render_as_string(hide_password=False)
    engine=create_engine(url);local=sessionmaker(bind=engine,expire_on_commit=False,autoflush=False)
    try:
        command.upgrade(config(url),'head')
        monkeypatch.setattr(settings,'DATABASE_URL',url)
        monkeypatch.setattr(settings,'DEMO_MODE',True)
        monkeypatch.setattr(settings,'APP_ENV','development')
        monkeypatch.setattr(main,'SessionLocal',local)
        monkeypatch.setattr(main,'engine',engine)
        def override():
            with local() as db:yield db
        main.app.dependency_overrides[get_db]=override
        with TestClient(main.app,headers={'X-SecureAccess-CSRF':'1'}) as client:
            assert client.post('/api/auth/login',json={'username':'alex.dev','password':'Password123!'}).status_code==200
            payload={'aws_account_id':'123456789012','aws_account_name':'Dev-Sandbox','iam_role':'JIT-Access-ReadOnly','duration_minutes':60,'justification':'PostgreSQL integration verification'}
            result=client.post('/api/requests',json=payload,headers={'Idempotency-Key':str(uuid.uuid4())})
            assert result.status_code==200,result.text
            session=client.get('/api/sessions/active').json()[0]
            assert client.post('/api/sessions/'+session['id']+'/revoke').status_code==200
            with local() as db,read_snapshot(db):assert audit_service.verify_chain_integrity(db)
            with engine.connect() as db:
                with pytest.raises(Exception):db.execute(text("DELETE FROM audit_logs"))
    finally:
        main.app.dependency_overrides.clear()
        engine.dispose()
        with base.begin() as db:db.execute(text('DROP SCHEMA '+schema+' CASCADE'))
        base.dispose()
