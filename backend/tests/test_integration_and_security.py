"""Integration, Engineer CLI, Change Detection & Topology Tests."""
from fastapi.testclient import TestClient
from app.main import app


def test_end_to_end_api_engineer_cli_and_topology():
    with TestClient(app) as client:
        # 1. Health check & independent statistical engine readiness
        res = client.get("/api/v1/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert data["inventoried_assets"] >= 5

        # 2. Dashboard KPIs & charts
        dash = client.get("/api/v1/dashboard").json()
        assert dash["kpis"]["total_discovered_assets"] >= 5
        assert dash["kpis"]["open_tcp_ports"] >= 8
        assert dash["kpis"]["open_udp_ports"] >= 2
        assert dash["kpis"]["service_mismatches"] >= 1

        # 3. Scan execution on single host and custom IP
        auth_scan = client.post(
            "/api/v1/scans",
            json={"target": "192.168.56.10", "scan_profile": "STANDARD_TCP_INTEL"},
        )
        assert auth_scan.status_code == 201
        scan_obj = auth_scan.json()
        assert scan_obj["status"] == "COMPLETED"
        assert scan_obj["target"] == "192.168.56.10"

        # 4. Topology hierarchy & Digital Twin comparison
        topo = client.get("/api/v1/topology").json()
        assert topo["stats"]["total_subnets"] >= 2
        assert topo["stats"]["total_hosts"] >= 5
        node_types = {n["type"] for n in topo["nodes"]}
        assert {"NETWORK_CORE", "SUBNET", "HOST", "SERVICE_PORT"}.issubset(node_types)

        snapshots = client.get("/api/v1/topology/snapshots").json()
        assert len(snapshots) >= 2
        diff = client.get(
            "/api/v1/topology/compare",
            params={
                "baseline_id": snapshots[-1]["snapshot_id"],
                "target_id": snapshots[0]["snapshot_id"],
            },
        )
        assert diff.status_code == 200
        diff_data = diff.json()
        assert "added_hosts" in diff_data
        assert "added_service_ports" in diff_data

        # 5. Hybrid Terminal unrestricted engineer commands (platform, shell, and AI)
        term_ok = client.post(
            "/api/v1/terminal/command",
            json={"command": "ports 192.168.56.10"},
        )
        assert term_ok.status_code == 200
        assert term_ok.json()["allowed"] is True
        assert "192.168.56.10" in term_ok.json()["output"]

        term_whoami = client.post(
            "/api/v1/terminal/command",
            json={"command": "whoami"},
        )
        assert term_whoami.status_code == 200
        assert term_whoami.json()["allowed"] is True
        assert "[SECURITY BLOCK]" not in term_whoami.json()["output"]

        term_ai = client.post(
            "/api/v1/terminal/command",
            json={"command": "ai List all critical database exposures"},
        )
        assert term_ai.status_code == 200
        assert term_ai.json()["allowed"] is True
        assert "NETSENTINEL AI" in term_ai.json()["output"]

        # 6. Autonomous Exposure Investigator, Volatility Predictions & Hybrid AI Investigation
        investigations = client.get("/api/v1/investigations").json()
        assert len(investigations) >= 1
        assert len(investigations[0]["steps_completed_json"]) == 7

        predictions = client.get("/api/v1/changes/predictions").json()
        assert len(predictions) >= 5

        ai_res = client.post(
            "/api/v1/ai/investigate",
            json={"question": "Which newly exposed database ports pose the highest risk?"},
        )
        assert ai_res.status_code == 200
        assert "NETSENTINEL AI" in ai_res.json()["answer_markdown"]

        # 7. Reporting exports (CSV, JSON, Printable HTML)
        csv_res = client.get("/api/v1/reports/csv")
        assert csv_res.status_code == 200
        assert "192.168.56.10" in csv_res.text

        html_res = client.get("/api/v1/reports/html")
        assert html_res.status_code == 200
        assert "NETSENTINEL AI" in html_res.text
