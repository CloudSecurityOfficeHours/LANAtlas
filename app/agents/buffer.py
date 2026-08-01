# agent/buffer.py
def submit_with_retry(observation: ObservationV1):
    try:
        api_client.post(observation)
    except ConnectionError:
        local_buffer.enqueue(observation)   # survive offline periods