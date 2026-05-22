import json


class ConfigLoader:

    def __init__(self):

        self.config_path = (
            "config/settings.json"
        )

    def load_config(self):

        with open(
            self.config_path,
            "r"
        ) as config_file:

            config = json.load(
                config_file
            )

        return config
