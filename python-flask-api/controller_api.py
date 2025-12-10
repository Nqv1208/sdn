from flask import Flask, jsonify, request, render_template
from pathlib import Path

from app import state_store, command_store


app = Flask(
    __name__,
    template_folder=str(Path(__file__).resolve().parent / "templates"),
    static_folder=str(Path(__file__).resolve().parent / "static"),
)


def _latest_state():
    return state_store.read_latest_state() or {}


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/state")
def api_state():
    return jsonify(_latest_state())


@app.route("/api/summary")
def api_summary():
    state = _latest_state()
    return jsonify(
        {
            "network": state.get("network", {}),
            "stats": state.get("stats", {}),
            "threats": state.get("threats", {}),
            "thresholds": state.get("thresholds", {}),
            "updated_at": state.get("updated_at"),
        }
    )


@app.route("/api/switches")
def api_switches():
    state = _latest_state()
    return jsonify(state.get("network", {}).get("switches", []))


@app.route("/api/hosts")
def api_hosts():
    state = _latest_state()
    return jsonify(state.get("hosts", {}))


@app.route("/api/flows")
def api_flows():
    state = _latest_state()
    return jsonify(state.get("flows", {}))


@app.route("/api/ports")
def api_ports():
    state = _latest_state()
    return jsonify(state.get("ports", {}))


@app.route("/api/anomalies")
def api_anomalies():
    state = _latest_state()
    return jsonify(state.get("anomaly_scores", {}))


@app.route("/api/qos")
def api_qos():
    state = _latest_state()
    return jsonify(state.get("qos_config", {}))


@app.route("/api/commands/block", methods=["POST"])
def api_block():
    payload = request.get_json(force=True)
    ip_address = (payload or {}).get("ip")
    if not ip_address:
        return jsonify({"error": "Missing ip"}), 400

    command_store.enqueue_command("block_ip", {"ip": ip_address})
    return jsonify({"status": "queued", "ip": ip_address})


@app.route("/api/commands/unblock", methods=["POST"])
def api_unblock():
    payload = request.get_json(force=True)
    ip_address = (payload or {}).get("ip")
    if not ip_address:
        return jsonify({"error": "Missing ip"}), 400

    command_store.enqueue_command("unblock_ip", {"ip": ip_address})
    return jsonify({"status": "queued", "ip": ip_address})


@app.route("/api/commands/whitelist", methods=["POST"])
def api_whitelist():
    payload = request.get_json(force=True)
    ip_address = (payload or {}).get("ip")
    if not ip_address:
        return jsonify({"error": "Missing ip"}), 400

    command_store.enqueue_command("whitelist_ip", {"ip": ip_address})
    return jsonify({"status": "queued", "ip": ip_address})


@app.route("/api/commands/whitelist/remove", methods=["POST"])
def api_remove_whitelist():
    payload = request.get_json(force=True)
    ip_address = (payload or {}).get("ip")
    if not ip_address:
        return jsonify({"error": "Missing ip"}), 400

    command_store.enqueue_command("remove_whitelist_ip", {"ip": ip_address})
    return jsonify({"status": "queued", "ip": ip_address})


@app.route("/api/commands/thresholds", methods=["POST"])
def api_thresholds():
    payload = request.get_json(force=True) or {}
    command_store.enqueue_command("set_thresholds", payload)
    return jsonify({"status": "queued", "updated": list(payload.keys())})


@app.route("/api/commands/qos/set", methods=["POST"])
def api_qos_set():
    payload = request.get_json(force=True) or {}
    ip_address = payload.get("ip")
    rate_kbps = payload.get("rate_kbps")
    
    if not ip_address or not rate_kbps:
        return jsonify({"error": "Missing ip or rate_kbps"}), 400
    
    if not isinstance(rate_kbps, (int, float)) or rate_kbps <= 0:
        return jsonify({"error": "rate_kbps must be a positive number"}), 400
    
    command_payload = {
        "ip": ip_address,
        "rate_kbps": int(rate_kbps),
    }
    
    if "burst_kb" in payload:
        command_payload["burst_kb"] = int(payload["burst_kb"])
    
    command_store.enqueue_command("set_qos", command_payload)
    return jsonify({"status": "queued", "ip": ip_address, "rate_kbps": rate_kbps})


@app.route("/api/commands/qos/remove", methods=["POST"])
def api_qos_remove():
    payload = request.get_json(force=True) or {}
    ip_address = payload.get("ip")
    
    if not ip_address:
        return jsonify({"error": "Missing ip"}), 400
    
    command_store.enqueue_command("remove_qos", {"ip": ip_address})
    return jsonify({"status": "queued", "ip": ip_address})


def create_app():
    return app


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

