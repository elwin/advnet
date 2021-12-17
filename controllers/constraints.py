import csv
import dataclasses
import typing


@dataclasses.dataclass(frozen=True)
class Waypoint:
    src: str
    dst: str
    via: str


def load_waypoints(path: str) -> typing.List[Waypoint]:
    waypoints: typing.List[Waypoint] = []
    with open(path) as csv_file:
        for row in csv.reader(csv_file):
            if not row[0].startswith('wp_'):
                continue

            waypoints.append(Waypoint(
                src=row[1][:3],
                dst=row[2][:3],
                via=row[7],
            ))

    return waypoints
