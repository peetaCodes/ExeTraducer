# analyzer_dynamic/wine_runner.py
import subprocess
import os
import datetime

class WineRunner:
    def __init__(self, wine_path="wine", output_dir="reports/wine_logs"):
        self.wine_path = wine_path
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def run_with_debug(self, exe_path: str, args=None, debug_channel="relay"):
        """
        Esegue un programma tramite Wine con il debug attivo.
        :param exe_path: percorso all'exe Windows
        :param args: lista di argomenti aggiuntivi
        :param debug_channel: canale WINEDEBUG (default relay)
        :return: percorso del file di log generato
        """
        if args is None:
            args = []

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(self.output_dir, f"wine_relay_{timestamp}.log")

        cmd = [
            "env", f"WINEDEBUG=+{debug_channel}",
            self.wine_path, exe_path
        ] + args

        with open(log_file, "w") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)

        return log_file
