from flask import Flask, request, jsonify
import redis, json
import re

redis_server = redis.Redis()
redis_server2 = redis.Redis()

app = Flask(__name__)

def main():
    @app.route('/remaining_tasks', methods=['GET'])
    def get_remaining_tasks():
        # Calculate the number of remaining tasks in the Redis queue
        q_len = redis_server.llen('api_req_queue')
        return jsonify({"remaining_tasks": q_len})

    @app.route('/current_task', methods=['GET'])
    def get_current_task():
        # Retrieve information about the current task being processed
        task_info = redis_server2.get("current_task")  # Set this key when you start processing a task
        if task_info:
            task_info = task_info.decode()  # Decode from bytes to string
            task_dict = json.loads(task_info)
        else:
            task_dict = {}
        return jsonify({"current_task": task_dict})

    @app.route('/clear_cache', methods=['POST'])
    def clear_cache():
        # Clear the Redkil.lis cache (delete all keys)
        redis_server.flushall()
        return jsonify({"message": "Redis cache cleared"})

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000, debug=True)
  
