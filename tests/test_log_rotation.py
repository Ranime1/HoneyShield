
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "eve_test.json"

    # Simuler un journal contenant des événements
    path.write_text(
        '{"event_type":"alert","id":1}\n'
        '{"event_type":"alert","id":2}\n',
        encoding="utf-8"
    )

    with path.open("r", encoding="utf-8") as file:
        file.seek(0, 2)

        previous_position = file.tell()
        print("Position avant rotation :", previous_position)

        # Simuler une rotation copytruncate
        path.write_text("", encoding="utf-8")

        current_size = path.stat().st_size

        if current_size < file.tell():
            print("Rotation detectee")
            file.seek(0)

        # Simuler l'arrivée d'un nouvel événement
        with path.open("a", encoding="utf-8") as writer:
            writer.write(
                '{"event_type":"alert","id":3}\n'
            )

        line = file.readline()
        print("Nouvel evenement lu :", line.strip())

        assert "Rotation detectee" if current_size < previous_position else False
        assert '"id":3' in line

print("Test de rotation reussi")
