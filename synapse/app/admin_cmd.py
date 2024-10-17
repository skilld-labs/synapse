#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2019 Matrix.org Foundation C.I.C.
# Copyright (C) 2023 New Vector, Ltd
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# See the GNU Affero General Public License for more details:
# <https://www.gnu.org/licenses/agpl-3.0.html>.
#
# Originally licensed under the Apache License, Version 2.0:
# <http://www.apache.org/licenses/LICENSE-2.0>.
#
# [This file includes modifications made by New Vector Limited]
#
#
import argparse
import json
import logging
import os
import sys
import tempfile
from typing import List, Mapping, Optional, Sequence

from twisted.internet import defer, task

import synapse
from synapse.app import _base
from synapse.config._base import ConfigError
from synapse.config.homeserver import HomeServerConfig
from synapse.config.logger import setup_logging
from synapse.events import EventBase
from synapse.handlers.admin import ExfiltrationWriter
from synapse.server import HomeServer
from synapse.storage.database import DatabasePool, LoggingDatabaseConnection
from synapse.storage.databases.main.account_data import AccountDataWorkerStore
from synapse.storage.databases.main.appservice import (
    ApplicationServiceTransactionWorkerStore,
    ApplicationServiceWorkerStore,
)
from synapse.storage.databases.main.client_ips import ClientIpWorkerStore
from synapse.storage.databases.main.deviceinbox import DeviceInboxWorkerStore
from synapse.storage.databases.main.devices import DeviceWorkerStore
from synapse.storage.databases.main.event_federation import EventFederationWorkerStore
from synapse.storage.databases.main.event_push_actions import (
    EventPushActionsWorkerStore,
)
from synapse.storage.databases.main.events_worker import EventsWorkerStore
from synapse.storage.databases.main.filtering import FilteringWorkerStore
from synapse.storage.databases.main.media_repository import MediaRepositoryStore
from synapse.storage.databases.main.profile import ProfileWorkerStore
from synapse.storage.databases.main.push_rule import PushRulesWorkerStore
from synapse.storage.databases.main.receipts import ReceiptsWorkerStore
from synapse.storage.databases.main.registration import RegistrationWorkerStore
from synapse.storage.databases.main.relations import RelationsWorkerStore
from synapse.storage.databases.main.room import RoomWorkerStore
from synapse.storage.databases.main.roommember import RoomMemberWorkerStore
from synapse.storage.databases.main.signatures import SignatureWorkerStore
from synapse.storage.databases.main.state import StateGroupWorkerStore
from synapse.storage.databases.main.stream import StreamWorkerStore
from synapse.storage.databases.main.tags import TagsWorkerStore
from synapse.storage.databases.main.user_erasure_store import UserErasureWorkerStore
from synapse.types import JsonMapping, StateMap
from synapse.util import SYNAPSE_VERSION
from synapse.util.logcontext import LoggingContext

logger = logging.getLogger("synapse.app.admin_cmd")


class AdminCmdStore(
    FilteringWorkerStore,
    ClientIpWorkerStore,
    DeviceWorkerStore,
    TagsWorkerStore,
    DeviceInboxWorkerStore,
    AccountDataWorkerStore,
    PushRulesWorkerStore,
    ApplicationServiceTransactionWorkerStore,
    ApplicationServiceWorkerStore,
    RoomMemberWorkerStore,
    RelationsWorkerStore,
    EventFederationWorkerStore,
    EventPushActionsWorkerStore,
    StateGroupWorkerStore,
    SignatureWorkerStore,
    UserErasureWorkerStore,
    ReceiptsWorkerStore,
    StreamWorkerStore,
    EventsWorkerStore,
    RegistrationWorkerStore,
    RoomWorkerStore,
    ProfileWorkerStore,
    MediaRepositoryStore,
):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        # Annoyingly `filter_events_for_client` assumes that this exists. We
        # should refactor it to take a `Clock` directly.
        self.clock = hs.get_clock()


class AdminCmdServer(HomeServer):
    DATASTORE_CLASS = AdminCmdStore  # type: ignore


from typing import Dict
from synapse.storage.database import LoggingTransaction
from synapse.storage.databases.main.events_worker import ExtendedRuntimeError


def _update_event_ids_txn(txn: LoggingTransaction, old_event_id: str, new_event_id: str):
    txn.execute("UPDATE event_id_mapping SET new_event_id = ? WHERE event_id = ?",
                (new_event_id, old_event_id))
    mapping = txn.rowcount
    txn.execute("UPDATE events SET event_id = ? WHERE event_id = ?",
                (new_event_id, old_event_id))
    events = txn.rowcount
    txn.execute("UPDATE event_json SET event_id = ? WHERE event_id = ?",
                (new_event_id, old_event_id))
    event_json = txn.rowcount
    #print(f"Changed mapping:{mapping} event_json:{event_json} events:{events}")

async def _process_event_update(store, old_event_id, new_event_id):
    try:
        await store.db_pool.runInteraction(
            "update_event_ids",
            _update_event_ids_txn,
            old_event_id, new_event_id,
            db_autocommit=True
        )
        return True
    except Exception as ex:
        #print(f"Failed to update event {old_event_id}: {ex}")
        return False


async def _validate_update_event_json(store, event_id: str, old_to_new: Dict[str, str], new_to_old: Dict[str, str]):
    try:
        #print(f"validaite json {event_id}")
        rows = await store.db_pool.simple_select_one(
            table="event_json",
            keyvalues={"event_id": event_id},
            retcols=("json",)
        )
        data = json.loads(rows[0])

        fields_to_update = ['auth_events', 'prev_events']
        updated = False

        for field in fields_to_update:
            if field not in data:
                continue

            for i, eid in enumerate(data[field]):
                if new_to_old.get(eid) is None:
                    new_id = old_to_new[eid]
                    data[field][i] = new_id
                    updated |= True

        if updated:
            updated_json = json.dumps(data, indent=None, separators=(",", ":"))
            await store.db_pool.simple_update_one(
                desc="update_event_json_hashes",
                table="event_json",
                keyvalues={"event_id": event_id},
                updatevalues={"json": updated_json},
            )
            #print(f"saved updated json for {event_id}")
            return 2

        return 1
    except Exception as exa:
        #print(f"Failed to update event_json and mapping for {event_id}: {exa}")
        return 0


async def process_room_events(hs: HomeServer, args: argparse.Namespace) -> None:
    """Process room events."""

    room_id = args.room_id
    print(f"Processing room {room_id}...")

    store = hs.get_datastores().main

    #  e.room_id='!fCeEXSqGyxLMdBEUsb:utterance-bus.fastr.cloud'
    event_ids = await store.db_pool.execute(
        "get_room_events_new_or_old_and_old_for_new_ordered",
        """
            SELECT e.event_id AS eid, m.event_id AS old
            FROM events e
            LEFT JOIN event_id_mapping m
            ON m.new_event_id=e.event_id
            WHERE e.room_id = ?
            ORDER BY e.stream_ordering ASC
            """,
        room_id
    )
    events_in_room = len(event_ids)
    mapping_rows = await store.db_pool.execute(
        "get_event_mapping_old_to_new",
        """
            SELECT m.event_id AS old, m.new_event_id AS new 
            FROM events e
            LEFT JOIN event_id_mapping m
            ON m.new_event_id=e.event_id
            WHERE room_id = ?
            """,
        room_id
    )
    mapping: Dict[str, str] = {row[0]: row[1] for row in mapping_rows}
    mapping_size = len(mapping)
    print(f"Mapping size {mapping_size}")

    # ensures only processed room events can be used for reverse mapping
    new_to_old = {}

    count = 0
    loaded = 0
    update = 0
    update_json = 0

    for row in event_ids:
        count += 1
        if count%100 == 0:
            print(f"Processing {row} {count}/{events_in_room}")
        eid, old_id = row
        loop_it = True

        while loop_it:
            new_id = await _event_need_new_hash(store, eid)
            if new_id is False:
                if old_id is not None:
                    #print(f"Event {eid} hash already recalculated from {old_id}")
                    new_to_old[eid] = old_id
                    loaded += 1
                    break
                else:
                    print(f"mapping for {eid} is missing but pass validation")
                    exit(1)

            # check json hashes and update if required
            state = await _validate_update_event_json(store, eid, mapping, new_to_old)
            if state == 0:
                print(f"Failed to update JSON for {eid}")
                exit(1)
            elif state == 2:
                continue

            # update mapping and event_id
            loop_it = await _process_event_update(store, eid, new_id)
            if loop_it:
                #print(f"Successfully updated event {eid} with new hash {new_id}")
                old_id = eid
                eid = new_id
                mapping[old_id] = new_id

    print(f"Total {count}\n Loaded {loaded}\n Updated {update}\n JSON updates {update_json}")
    exit(0)


async def export_data_command(hs: HomeServer, args: argparse.Namespace) -> None:
    """Export data for a user."""

    user_id = args.user_id
    directory = args.output_directory

    res = await hs.get_admin_handler().export_user_data(
        user_id, FileExfiltrationWriter(user_id, directory=directory)
    )
    print(res)


async def validate_room_events(hs: HomeServer, args: argparse.Namespace) -> None:
    from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
    from synapse.events import make_event_from_dict
    from synapse.storage._base import db_to_json

    room_id = args.room_id
    domain_old = args.domain_old
    domain_new = args.domain_new
    domain_old = "utterance-bus.fastr.cloud"
    domain_new = "message-bus.skilld.cloud"
    print(f"Processing room {room_id}...")

    # see _fetch_event_rows()
    store = hs.get_datastores().main
    events = await store.db_pool.execute(
        "get_room_events_new_or_old_and_old_for_new_ordered",
        """
        SELECT
          e.event_id,
          e.stream_ordering,
          ej.internal_metadata,
          ej.json,
          ej.format_version,
          r.room_version,
          rej.reason,
          e.outlier
        FROM events AS e
          JOIN event_json AS ej USING (event_id)
          LEFT JOIN rooms r ON r.room_id = e.room_id
          LEFT JOIN rejections as rej USING (event_id)
        WHERE e.room_id = ?
        ORDER BY e.stream_ordering ASC
        """,
        room_id
    )
    events_in_room = len(events)
    print(f"events found {events_in_room}")

    room_is_new = domain_new in room_id
    counter = 0
    old_to_new = {}
    for row in events:
        counter += 1
        eid = row[0]
        print(f"Processing {eid} - {counter}")

        room_version = KNOWN_ROOM_VERSIONS.get(row[5])
        internal_metadata = {} # db_to_json(row[2])
        rejected_reason = row[6]
        json = row[3]
        if room_is_new:
            json_new = json.replace(domain_new, domain_old)
        else:
            json_new = json.replace(domain_old, domain_new)
        event = make_event_from_dict(
            event_dict=db_to_json(json),
            room_version=room_version,
            internal_metadata_dict=internal_metadata,
            rejected_reason=rejected_reason,
        )
        event_new = make_event_from_dict(
            event_dict=db_to_json(json_new),
            room_version=room_version,
            internal_metadata_dict=internal_metadata,
            rejected_reason=rejected_reason,
        )
        # validate and update parent events
        fields_to_update = ['auth_events', 'prev_events']
        missing_parents = {}
        for field in fields_to_update:
            if field not in event:
                continue

            for i, id in enumerate(event_new[field]):
                if old_to_new.get(id) is None:
                    missing_parents.setdefault(field, set()).add(id)
                    continue
                event_new[field][i] = old_to_new[id]
        if missing_parents:
            print(f"missing parents {missing_parents} for {eid}")
            exit(1)

        new_id = event_new.event_id
        print(f"current room {event.room_id} sender {event.sender}")
        print(f"auth {event.auth_event_ids()}")
        print(f"prev {event.prev_event_ids()}")
        print(f"new event {new_id} in room {event_new.room_id} sender {event_new.sender}")
        print(f"auth {event_new.auth_event_ids()}")
        print(f"prev {event_new.prev_event_ids()}")
        if new_id != eid:
            print(f"new event {new_id} should replace {eid}")
        else:
            print(f"skip, event hash valid")
        old_to_new[eid] = new_id


class FileExfiltrationWriter(ExfiltrationWriter):
    """An ExfiltrationWriter that writes the users data to a directory.
    Returns the directory location on completion.

    Note: This writes to disk on the main reactor thread.

    Args:
        user_id: The user whose data is being exfiltrated.
        directory: The directory to write the data to, if None then will write
            to a temporary directory.
    """

    def __init__(self, user_id: str, directory: Optional[str] = None):
        self.user_id = user_id

        if directory:
            self.base_directory = directory
        else:
            self.base_directory = tempfile.mkdtemp(
                prefix="synapse-exfiltrate__%s__" % (user_id,)
            )

        os.makedirs(self.base_directory, exist_ok=True)
        if list(os.listdir(self.base_directory)):
            raise Exception("Directory must be empty")

    def write_events(self, room_id: str, events: List[EventBase]) -> None:
        room_directory = os.path.join(self.base_directory, "rooms", room_id)
        os.makedirs(room_directory, exist_ok=True)
        events_file = os.path.join(room_directory, "events")

        with open(events_file, "a") as f:
            for event in events:
                json.dump(event.get_pdu_json(), fp=f)

    def write_state(
        self, room_id: str, event_id: str, state: StateMap[EventBase]
    ) -> None:
        room_directory = os.path.join(self.base_directory, "rooms", room_id)
        state_directory = os.path.join(room_directory, "state")
        os.makedirs(state_directory, exist_ok=True)

        event_file = os.path.join(state_directory, event_id)

        with open(event_file, "a") as f:
            for event in state.values():
                json.dump(event.get_pdu_json(), fp=f)

    def write_invite(
        self, room_id: str, event: EventBase, state: StateMap[EventBase]
    ) -> None:
        self.write_events(room_id, [event])

        # We write the invite state somewhere else as they aren't full events
        # and are only a subset of the state at the event.
        room_directory = os.path.join(self.base_directory, "rooms", room_id)
        os.makedirs(room_directory, exist_ok=True)

        invite_state = os.path.join(room_directory, "invite_state")

        with open(invite_state, "a") as f:
            for event in state.values():
                json.dump(event, fp=f)

    def write_knock(
        self, room_id: str, event: EventBase, state: StateMap[EventBase]
    ) -> None:
        self.write_events(room_id, [event])

        # We write the knock state somewhere else as they aren't full events
        # and are only a subset of the state at the event.
        room_directory = os.path.join(self.base_directory, "rooms", room_id)
        os.makedirs(room_directory, exist_ok=True)

        knock_state = os.path.join(room_directory, "knock_state")

        with open(knock_state, "a") as f:
            for event in state.values():
                json.dump(event, fp=f)

    def write_profile(self, profile: JsonMapping) -> None:
        user_directory = os.path.join(self.base_directory, "user_data")
        os.makedirs(user_directory, exist_ok=True)
        profile_file = os.path.join(user_directory, "profile")

        with open(profile_file, "a") as f:
            json.dump(profile, fp=f)

    def write_devices(self, devices: Sequence[JsonMapping]) -> None:
        user_directory = os.path.join(self.base_directory, "user_data")
        os.makedirs(user_directory, exist_ok=True)
        device_file = os.path.join(user_directory, "devices")

        for device in devices:
            with open(device_file, "a") as f:
                json.dump(device, fp=f)

    def write_connections(self, connections: Sequence[JsonMapping]) -> None:
        user_directory = os.path.join(self.base_directory, "user_data")
        os.makedirs(user_directory, exist_ok=True)
        connection_file = os.path.join(user_directory, "connections")

        for connection in connections:
            with open(connection_file, "a") as f:
                json.dump(connection, fp=f)

    def write_account_data(
        self, file_name: str, account_data: Mapping[str, JsonMapping]
    ) -> None:
        account_data_directory = os.path.join(
            self.base_directory, "user_data", "account_data"
        )
        os.makedirs(account_data_directory, exist_ok=True)

        account_data_file = os.path.join(account_data_directory, file_name)

        with open(account_data_file, "a") as f:
            json.dump(account_data, fp=f)

    def write_media_id(self, media_id: str, media_metadata: JsonMapping) -> None:
        file_directory = os.path.join(self.base_directory, "media_ids")
        os.makedirs(file_directory, exist_ok=True)
        media_id_file = os.path.join(file_directory, media_id)

        with open(media_id_file, "w") as f:
            json.dump(media_metadata, fp=f)

    def finished(self) -> str:
        return self.base_directory


def start(config_options: List[str]) -> None:
    parser = argparse.ArgumentParser(description="Synapse Admin Command")
    HomeServerConfig.add_arguments_to_parser(parser)

    subparser = parser.add_subparsers(
        title="Admin Commands",
        required=True,
        dest="command",
        metavar="<admin_command>",
        help="The admin command to perform.",
    )
    export_data_parser = subparser.add_parser(
        "export-data", help="Export all data for a user"
    )
    export_data_parser.add_argument("user_id", help="User to extra data from")
    export_data_parser.add_argument(
        "--output-directory",
        action="store",
        metavar="DIRECTORY",
        required=False,
        help="The directory to store the exported data in. Must be empty. Defaults"
        " to creating a temp directory.",
    )
    export_data_parser.set_defaults(func=export_data_command)
    root_items_parser = subparser.add_parser(
            "root-items", help="Migrate root events"
    )
    root_items_parser.set_defaults(func=update_root_items)
    room_events_parser = subparser.add_parser(
            "room-events", help="Process room events"
    )
    room_events_parser.add_argument("room_id", help="Room ID to list events")
    room_events_parser.set_defaults(func=process_room_events)
    room_val_parser = subparser.add_parser(
            "room-val", help="Validate room events"
    )
    room_val_parser.add_argument("room_id", help="Room ID to list events")
    room_val_parser.add_argument("from", help="Domain TLD to replace for events")
    room_val_parser.add_argument("to", help="Domain TLD for new events")
    room_val_parser.set_defaults(func=validate_room_events)

    try:
        config, args = HomeServerConfig.load_config_with_parser(parser, config_options)
    except ConfigError as e:
        sys.stderr.write("\n" + str(e) + "\n")
        sys.exit(1)

    if config.worker.worker_app is not None:
        assert config.worker.worker_app == "synapse.app.admin_cmd"

    # Update the config with some basic overrides so that don't have to specify
    # a full worker config.
    config.worker.worker_app = "synapse.app.admin_cmd"

    if not config.worker.worker_daemonize and not config.worker.worker_log_config:
        # Since we're meant to be run as a "command" let's not redirect stdio
        # unless we've actually set log config.
        config.logging.no_redirect_stdio = True

    # Explicitly disable background processes
    config.worker.should_update_user_directory = False
    config.worker.run_background_tasks = False
    config.worker.start_pushers = False
    config.worker.pusher_shard_config.instances = []
    config.worker.send_federation = False
    config.worker.federation_shard_config.instances = []

    synapse.events.USE_FROZEN_DICTS = config.server.use_frozen_dicts

    ss = AdminCmdServer(
        config.server.server_name,
        config=config,
        version_string=f"Synapse/{SYNAPSE_VERSION}",
    )

    setup_logging(ss, config, use_worker_options=True)

    ss.setup()

    # We use task.react as the basic run command as it correctly handles tearing
    # down the reactor when the deferreds resolve and setting the return value.
    # We also make sure that `_base.start` gets run before we actually run the
    # command.

    async def run() -> None:
        with LoggingContext("command"):
            await _base.start(ss)
            await args.func(ss, args)

    _base.start_worker_reactor(
        "synapse-admin-cmd",
        config,
        run_command=lambda: task.react(lambda _reactor: defer.ensureDeferred(run())),
    )


if __name__ == "__main__":
    with LoggingContext("main"):
        start(sys.argv[1:])
