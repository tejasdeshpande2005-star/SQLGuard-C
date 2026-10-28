"""
Tricky Case 3: Calling .execute() on a non-database object.
Syntactic pattern matchers looking only for call attribute 'execute'
will report a false positive on non-SQL execution sinks.
"""
class TaskExecutor:
    def __init__(self):
        self.log = []

    def execute(self, command_name: str):
        # Not a database sink; simply records task execution
        self.log.append(command_name)
        return f"Executed task: {command_name}"

def run_user_task():
    task_name = input("Enter task name: ")
    executor = TaskExecutor()
    # String concatenation into execute(), but NOT a SQL sink
    message = "run_" + task_name
    return executor.execute(message)

if __name__ == "__main__":
    print(run_user_task())
