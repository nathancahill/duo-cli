import glob
import os.path
import pathlib
import sqlite3

__all__ = ["get_backup"]

MANIFESTS = "~/Library/Application Support/MobileSync/Backup/*/Manifest.db"
PLIST_PATH = "Library/Preferences/com.duosecurity.DuoMobile.plist"


def file_stats(path):
    p = pathlib.Path(path)
    return (path, p.stat().st_mtime)


def find_manifests():
    return glob.glob(os.path.expanduser(MANIFESTS))


def recent_manifest(manifests):
    stats = list(map(file_stats, manifests))
    stats.sort(key=lambda p: p[1], reverse=True)

    return stats[0][0]


def search_manifest(manifest):
    conn = sqlite3.connect(manifest)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            fileId
        FROM
            Files
        WHERE
            relativePath = ?
    """,
        (PLIST_PATH,),
    )

    row = cur.fetchone()
    conn.close()

    if not row:
        return

    return row[0]


def id_to_path(manifest_path, file_id):
    base = os.path.dirname(manifest_path)
    return os.path.join(base, file_id[:2], file_id)


def get_backup():
    manifests = find_manifests()

    if not len(manifests):
        print("no man")
        return

    recent = recent_manifest(manifests)

    if not recent:
        return

    file_id = search_manifest(recent)

    if not file_id:
        return

    return id_to_path(recent, file_id)
