import logging


class FrameworkLogger:

    def __init__(self):

        self.logger = logging.getLogger(
            "ThreatSurfaceFramework"
        )

        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:

            file_handler = logging.FileHandler(
                "logs/framework.log"
            )

            formatter = logging.Formatter(
                "%(asctime)s | "
                "%(levelname)s | "
                "%(message)s"
            )

            file_handler.setFormatter(
                formatter
            )

            self.logger.addHandler(
                file_handler
            )

    def info(self, message):

        self.logger.info(message)

    def warning(self, message):

        self.logger.warning(message)

    def error(self, message):

        self.logger.error(message)
