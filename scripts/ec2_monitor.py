from watchdog.observers import Observer
from watchdog.events import FileSystemEvent, RegexMatchingEventHandler
from nightfall import Nightfall

import logging
import os

class CustomHandler(RegexMatchingEventHandler):
  nf = Nightfall(
    key=os.getenv("NIGHTFALL_API_KEY"),
    signing_secret=os.getenv("NIGHTFALL_SIGNING_SECRET"),
  )
  logger = logging.getLogger(__name__)

  def scan_file(self, path):
    try:
      scan_id, message = self.nf.scan_file(
        path,
        policy_uuid=os.getenv("NIGHTFALL_POLICY_UUID"),
      )
      return scan_id, message
    except Exception as e:
      return None, str(e)
    
  def on_modified(self, event: FileSystemEvent) -> None:
    path = event.src_path
    if not event.is_directory:
      self.logger.info(f"file modified: {path}")
      self.scan_file(path)

  def on_moved(self, event: FileSystemEvent) -> None:
    path = event.dest_path
    if not event.is_directory:
      self.logger.info(f"file moved: {path}")
      self.scan_file(path)
  
  def on_created(self, event: FileSystemEvent) -> None:
    if not event.is_directory:
      self.logger.info(f"file created: {event.src_path}")
      with open(event.src_path, "rb") as file:
        if len(file.read()) > 8:
          self.scan_file(event.src_path)

  def on_deleted(self, event: FileSystemEvent) -> None:
    if not event.is_directory:
      self.logger.info(f"file deleted: {event.src_path}")
  

if __name__ == "__main__":
  regexes = [r".*\.swp$", r".*\.swx"]

  event_handler = CustomHandler(ignore_regexes=regexes, case_sensitive=False)
  observer = Observer()
  observer.schedule(event_handler, path="/home", recursive=True)
  observer.start()

  while True:
    try:
      pass
    except KeyboardInterrupt:
      observer.stop()
      break
  observer.join()