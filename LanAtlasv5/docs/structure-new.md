lanatlas/
    cloud/                              # becomes lanatlas-cloud/ later
        app/
            schema/
                schema.sql               # full DDL — single source of truth, no ORM models
            migrations/                  # Alembic — hand-written, references schema.sql
                env.py
                versions/
                    0001_initial_schema.py
                    0002_add_audit_log.py

            config/
                identity.py              # SIGNAL_WEIGHTS, CONFIDENCE_THRESHOLDS, SCAN_TIERS,
                                          # TIER_CONFIDENCE_CEILING, HARDWARE_ANCHORED_SIGNALS ✅ built
                alerts.py                # MISSING_THRESHOLD_BY_TYPE ✅ built

            database/
                pool.py                  # SQLAlchemy engine, pool config      🔵 planned
                db.py                    # get_db(), get_test_db()            ✅ built
                transaction.py           # @transactional decorator            🔵 planned
                exceptions.py            # typed DB exceptions                 🔵 planned
                audit.py                 # AuditEvent, AuditAction, redact()  ✅ built
                logging.py               # DB query audit logging             🔵 planned

            repositories/
                devices.py               # ✅ built — includes rename/delete examples
                signals.py                # ✅ built
                observations.py           # ✅ built — includes insert_observation_if_new
                audit.py                  # ✅ built
                agents.py                 # lookup by api_key_hash, site ownership   🔴 gap — API1 blocker
                alerts.py                 # insert, update status, fetch unresolved  🔵 planned
                sites.py                  # business hours lookup                    🔵 planned
                users.py                  # oauth_subject lookup, role lookup        🔵 planned

            services/
                identity.py               # ✅ built
                deduplication.py          # ✅ built
                classification.py         # ✅ built
                thresholds.py             # ✅ built
                oui.py                    # lookup(mac) → vendor_name, reads data/oui.csv  🔵 planned
                alerting.py                # new_device/missing_device/new_port triggers    🔵 planned
                devices.py                 # rename/delete/authorize + audit wiring          🔴 gap
                alerts.py                  # acknowledge/resolve + audit wiring              🔴 gap
                users.py                   # role change + audit wiring                      🔴 gap
                agents.py                  # key rotation + audit wiring                     🔴 gap
                sites.py                   # business hours change + audit wiring            🔴 gap

            api/
                routes/
                    agents.py              # observation submission, heartbeat — imports ObservationV1 from protocol/
                    devices.py
                    alerts.py
                    sites.py
                    auth.py
                middleware/
                    auth.py                # JWT validation, org_id injection
                    rbac.py                # role enforcement per endpoint
                    rate_limit.py
                schemas/
                    devices.py             # DeviceOut — role-filtered response
                    alerts.py              # AlertOut, AlertStatusUpdate
                    auth.py                # TokenResponse, UserContext
                                            # NOTE: no observations.py here — that's protocol/'s job

            workers/
                alert_worker.py
                identity_worker.py
                cleanup_worker.py

            data/
                oui.csv                    # moved from repo root — only cloud/ reads this

        tests/
            conftest.py                    # ✅ built
            database/
                test_db.py
            repositories/
                test_devices.py
                test_observations.py
                test_signals.py
                test_audit.py
            services/
                test_identity.py           # ✅ built
                test_deduplication.py
            workers/
                test_alert_worker.py

        requirements.txt
        .env                              # DATABASE_URL, JWT secret, OAuth client secrets
        .gitignore

    agent/                              # becomes lanatlas-agent/ later
        scanner.py
        signer.py
        buffer.py
        heartbeat.py
        collector.py
        config.py                        # port ranges, protocol lists — moved out of cloud/config/scanning.py
        tests/
            test_scanner.py
            test_signer.py
            test_buffer.py
        requirements.txt                 # minimal by design
        .env                             # agent's own API key, cloud API URL — never DB creds

    protocol/                          # becomes lanatlas-protocol/ later
        schemas/
            observation_v1.py            # imported directly by cloud/app/api/routes/agents.py
            heartbeat_v1.py
            auth_handshake_v1.py
        tests/
            test_observation_schema.py
        VERSION
        CHANGELOG.md

    docs/
        schema-reference.md
        owasp-controls-mapping.md