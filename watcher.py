from imports import *


class RestartOnChangeHandler(FileSystemEventHandler):
    def __init__(self, script_path):
        self.script_path = script_path
        self.process = self.run_script()

    def run_script(self):
        print("🚀 Starting server...")
        return subprocess.Popen(["python", self.script_path])

    def on_any_event(self, event):
        if event.src_path.endswith(".py"):
            print(f"🔁 Change detected in: {event.src_path}. Restarting server...")
            self.process.kill()
            self.process = self.run_script()

if __name__ == "__main__":
    path = "."  # Watch current directory
    script_to_run = "main.py"  # Change this to your main script
    event_handler = RestartOnChangeHandler(script_to_run)
    observer = Observer()
    observer.schedule(event_handler, path=path, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        event_handler.process.kill()
    observer.join()