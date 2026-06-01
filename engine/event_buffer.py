import threading
import queue
import time
import requests
import os
from datetime import datetime, timezone
from engine.logger import get_logger

logger = get_logger(__name__)

MAX_QUEUE_SIZE = 10000
RETRY_INTERVAL = 5
MAX_RETRIES = 3

class EventBuffer:
    def __init__(self, es_url, es_user, es_password):
        self.es_url = es_url
        self.es_user = es_user
        self.es_password = es_password
        self.queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.running = True
        self.worker = threading.Thread(target=self._worker, daemon=True)
        self.worker.start()
        self.stats = {
            "sent": 0,
            "failed": 0,
            "dropped": 0,
            "queue_size": 0
        }
        logger.info("EventBuffer initialized — worker thread started")

    def put(self, doc):
        try:
            self.queue.put_nowait(doc)
            self.stats["queue_size"] = self.queue.qsize()
        except queue.Full:
            self.stats["dropped"] += 1
            logger.error(f"Event buffer full — event dropped. Total dropped: {self.stats['dropped']}")

    def _send(self, doc, retries=0):
        try:
            response = requests.post(
                self.es_url,
                json=doc,
                auth=(self.es_user, self.es_password),
                verify=False,
                timeout=5
            )
            if response.status_code in [200, 201]:
                self.stats["sent"] += 1
                return True
            else:
                logger.error(f"Elasticsearch error {response.status_code}: {response.text[:200]}")
                return False
        except requests.exceptions.ConnectionError:
            if retries < MAX_RETRIES:
                logger.warning(f"Elasticsearch unreachable — retry {retries + 1}/{MAX_RETRIES} in {RETRY_INTERVAL}s")
                time.sleep(RETRY_INTERVAL)
                return self._send(doc, retries + 1)
            else:
                logger.error(f"Elasticsearch unreachable after {MAX_RETRIES} retries — event queued for later")
                self.stats["failed"] += 1
                return False
        except Exception as e:
            logger.error(f"Unexpected error sending event: {e}")
            self.stats["failed"] += 1
            return False

    def _worker(self):
        logger.info("EventBuffer worker started")
        while self.running:
            try:
                doc = self.queue.get(timeout=1)
                self.stats["queue_size"] = self.queue.qsize()
                success = self._send(doc)
                if not success:
                    try:
                        self.queue.put_nowait(doc)
                        time.sleep(RETRY_INTERVAL)
                    except queue.Full:
                        self.stats["dropped"] += 1
                        logger.error("Cannot requeue event — buffer full")
                self.queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"EventBuffer worker error: {e}")

    def get_stats(self):
        return {
            **self.stats,
            "queue_size": self.queue.qsize()
        }

    def stop(self):
        self.running = False
        logger.info(f"EventBuffer stopped — stats: {self.get_stats()}")


_buffer = None

def init_buffer():
    global _buffer
    _buffer = EventBuffer(
        es_url=os.getenv("ES_URL", "https://localhost:9200/siem-events/_doc"),
        es_user=os.getenv("ES_USER", "elastic"),
        es_password=os.getenv("ES_PASSWORD", "SiemPME2026!")
    )
    return _buffer

def get_buffer():
    global _buffer
    if _buffer is None:
        return init_buffer()
    return _buffer
