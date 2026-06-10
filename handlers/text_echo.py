def handle(service, input_obj):
    text = str(input_obj.get("text", ""))
    return 200, "OK", {"reply": f"Agent received {len(text.encode('utf-8'))} bytes: {text}"}
