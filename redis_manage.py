import redis

redis_server = redis.Redis()
queue_name = "api_req_queue"

def redis_set(KEY="",VALUE=""):
    redis_server.set(name=KEY, value=VALUE)
    key_val = redis_server.get(KEY)
    print(key_val)

def redis_queue_push(ID):
    redis_server.rpush(queue_name, ID)

def redis_queue_get():
    req = redis_server.lpop(queue_name)
    return req

if __name__ == "__main__":
    redis_queue_push("646656")
    redis_queue_push("655446")
    redis_queue_push("700042")

    q_len = redis_server.llen(queue_name)
    requests_list = redis_server.lrange(queue_name, 0, q_len)

    for req in requests_list:
        next_req = redis_queue_get()
        print
        redis_set(next_req, "TO_DO")
        print(f"working on request id: {next_req} ")
        print(f"finish request id: {next_req} ")
        redis_set(next_req, "DONE")