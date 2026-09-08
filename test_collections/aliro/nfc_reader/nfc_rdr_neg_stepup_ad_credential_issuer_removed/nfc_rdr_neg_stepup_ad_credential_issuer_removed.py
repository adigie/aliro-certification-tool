#
# Copyright (c) 2023 Project Aliro Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import datetime

from aliro_actuator.access_protocol.apdu import (
    INS,
    ReaderStatus,
)
from aliro_actuator.access_protocol.defines import TransportProtocol
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidCommandError,
)
from aliro_actuator.access_protocol.user_device import UserDevice, UserSessionState
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.access_doc.aliro.access import AccessData
from ...support.access_doc.mdl.common import IssuerNamespaces, DocTypes
from ...support.access_doc.mdl.request import DeviceRequest
from ...support.access_doc.mdl.response.device_response_builder import DeviceResponseBuilder, ResponseElement
from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class NFC_RDR_NEG_STEPUP_AD_CREDENTIAL_ISSUER_REMOVED(
    AliroReaderTestCase, UserPromptSupport
):
    metadata = {
        "public_id": "NFC_RDR_NEG_STEPUP_AD_CREDENTIAL_ISSUER_REMOVED",
        "version": "0.0.1",
        "title": "NFC_RDR_NEG_STEPUP_AD_CREDENTIAL_ISSUER_REMOVED",
        "description": """Verify Step-Up Transaction when Credential Issuer is removed.""",
    }

    endpoint_ePuBK = bytes.fromhex(
        "045d75ab60136a2c54ff27b799ee157f3f3329435c0d"
        "f608de904c920ac29f72bd4274c2edc810a93e240bf5"
        "d6394a92c9766b690b2bf5128ae70d6e29257ea786"
    )  # from Test Vector
    endpoint_ePuBK_2 = bytes.fromhex(
        "04e4c78918408463a235923d36e74b71627dabc606f1"
        "b4189af78f755b6e1bf3f7640a7f360130ee4ad268bb"
        "5531878cdce3a3e84da5e2a04efd5e8e4611922f2b"
    )
    endpoint_ePrivK = bytes.fromhex(
        "70637ee9b40cee568567c69589276888edca7128bb13fb531f9c4f502d8cc65e"
    )  # from Test Vector
    endpoint_ePrivK_2 = bytes.fromhex(
        "a657c9604d5688676c322210a3d73e89fd9fffd7f60044ea9f3a52efc241925d"
    )

    accepted_validity_iteration = 9
    rolled_back_validity_iteration = 0

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "RD",
                "NFC",
                "RD24",
                "RD28",
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Initialization"),
            TestStep("Step2: Set Reader Device Under Test in polling mode"),
            TestStep(
                f"Step3: Transaction Initiation Step-Up "
                f"(validity_iteration={self.accepted_validity_iteration})"
            ),
            TestStep(
                f"Step4: Receive/Send AUTH0 command/response Step-Up "
                f"(validity_iteration={self.accepted_validity_iteration})"
            ),
            TestStep(
                f"Step5: Receive/Send AUTH1 command/response Step-Up "
                f"(validity_iteration={self.accepted_validity_iteration})"
            ),
            TestStep(
                f"Step6: Handle Step-up SELECT "
                f"(validity_iteration={self.accepted_validity_iteration})"
            ),
            TestStep(
                f"Step7: Handle ENVELOPE command/response "
                f"(validity_iteration={self.accepted_validity_iteration})"
            ),
            TestStep(
                f"Step8: Handle EXCHANGE command/response Step-Up "
                f"(validity_iteration={self.accepted_validity_iteration})"
            ),
            TestStep("Step9: User interaction between transactions"),
            TestStep(
                f"Step10: Transaction Initiation Step-Up "
                f"(validity_iteration={self.rolled_back_validity_iteration})"
            ),
            TestStep(
                f"Step11: Receive/Send AUTH0 command/response Step-Up "
                f"(validity_iteration={self.rolled_back_validity_iteration})"
            ),
            TestStep(
                f"Step12: Receive/Send AUTH1 command/response Step-Up "
                f"(validity_iteration={self.rolled_back_validity_iteration})"
            ),
            TestStep(
                f"Step13: Handle Step-up SELECT "
                f"(validity_iteration={self.rolled_back_validity_iteration})"
            ),
            TestStep(
                f"Step14: Handle ENVELOPE command/response "
                f"(validity_iteration={self.rolled_back_validity_iteration})"
            ),
            TestStep(
                f"Step15: Handle EXCHANGE command/response Step-Up "
                f"(validity_iteration={self.rolled_back_validity_iteration})"
            ),
        ]

    def build_access_document(
        self,
        access_credential_pk: bytes,
        validity_iteration: int,
        signed_time: datetime.datetime,
    ) -> bytes:
        issuer_keypair, _, self.element_id = self.access_document_data()

        access_element = AccessData()
        access_element.version = 1

        access_doc = DeviceResponseBuilder.build_doc(
            doc_type=DocTypes.ALIRO_ACCESS,
            namespace=IssuerNamespaces.ALIRO_ACCESS,
            data_elements=[
                ResponseElement(data_element_id=self.element_id, value=access_element)
            ],
            issuer_private_key=issuer_keypair.get_private_key().as_bytes(),
            device_public_key=access_credential_pk,
            valid_from=signed_time,
            valid_until=signed_time + datetime.timedelta(days=14),
            validity_iteration=validity_iteration,
            signed=signed_time,
        ).to_cbor()

        logger.info(
            f"Generated Access Document (validity_iteration={validity_iteration}, "
            f"signed={signed_time}): {access_doc.hex()}"
        )
        return access_doc

    def build_user_device(self, access_credential, access_doc: bytes) -> UserDevice:
        return UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[access_credential],
            mailbox=0x20,
            ephemeral_key_list=[
                KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK),
                KeyPair(self.endpoint_ePrivK_2, self.endpoint_ePuBK_2),
            ],
            access_document=access_doc,
            step_up_aid_required=True,
        )

    async def setup(self) -> None:
        logger.info("This is a test case setup")

        base_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            seconds=3
        )

        access_credential = self.reader_access_credential(use_random_ud_keypair=True)
        credential_pk = access_credential.get_access_credential_public_key().as_bytes()

        accepted_doc = self.build_access_document(
            credential_pk, self.accepted_validity_iteration, base_time
        )
        rolled_back_doc = self.build_access_document(
            credential_pk,
            self.rolled_back_validity_iteration,
            base_time + datetime.timedelta(seconds=1),
        )

        self.userdevice = self.build_user_device(access_credential, accepted_doc)
        self.rollback_device = self.build_user_device(access_credential, rolled_back_doc)

    async def _verify_device_request(self, envelope_payload: bytes) -> bool:
        device_request = DeviceRequest()
        if not device_request.from_cbor(envelope_payload):
            self.mark_step_failure("Failed to parse device request.")
            return False

        if not device_request.is_valid():
            self.mark_step_failure("Failed to validate device request.")
            return False

        found_element = False
        for doc_type, elm_req in [
            y
            for x in device_request.doc_requests
            for y in x.items_request.namespaces.data.items()
        ]:
            if doc_type != "aliro-a":
                continue
            if self.element_id in elm_req.keys():
                found_element = True

        if not found_element:
            self.mark_step_failure(
                f"Reader did not request Element ID {self.element_id}"
            )
            return False

        return True

    async def _do_stepup_transaction(
        self, userdevice: UserDevice, credential_name: str
    ) -> bool:
        """Perform a Step-Up transaction. Returns True on success, False on failure."""
        try:
            await userdevice.transaction_initiation()
        except (AccessProtocolError, InvalidCommandError) as error:
            self.mark_step_failure(str(error))
            return False
        self.next_step()

        try:
            cmds_auth0 = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False
        try:
            await userdevice.handle_auth0(cmds_auth0)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False
        if not userdevice.session.state_valid(UserSessionState.AUTH0_STD_DONE):
            self.mark_step_failure(
                f"Userdevice ({credential_name}) is not in state auth0 standard done, "
                "either fast transaction was requested or handling auth0 failed"
            )
            return False
        self.next_step()

        try:
            cmds_auth1 = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False
        try:
            await userdevice.handle_auth1(cmds_auth1)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False
        self.next_step()

        try:
            cmds_select = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False
        try:
            await userdevice.handle_select(cmds_select)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False
        self.next_step()

        try:
            cmds_envelope = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False

        if not await self._verify_device_request(cmds_envelope.decrypted_payload):
            return False

        try:
            await userdevice.handle_envelope(cmds_envelope)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False
        self.next_step()

        try:
            cmds_exchange = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False

        try:
            await userdevice.handle_exchange(cmds_exchange)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False

        if cmds_exchange.reader_status.value.to_bytes(2, "big")[0] != 0x01:
            self.mark_step_failure(
                "Received incorrect EXCHANGE reader status: 0x{:04x}".format(
                    cmds_exchange.reader_status.value
                )
            )
            return False
        self.next_step()

        return True

    async def _do_stepup_transaction_expect_refused(
        self, userdevice: UserDevice, credential_name: str
    ) -> tuple[bool, str | None]:
        """Perform a Step-Up transaction and expect access to be refused.

        Returns (True, None) when access is refused as expected.
        Returns (False, outcome_description) on protocol errors or unexpected grant.
        """
        outcome_description: str | None = None

        try:
            await userdevice.transaction_initiation()
        except (AccessProtocolError, InvalidCommandError) as error:
            self.mark_step_failure(str(error))
            return False, None
        self.next_step()

        try:
            cmds_auth0 = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False, None
        try:
            await userdevice.handle_auth0(cmds_auth0)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False, None
        if not userdevice.session.state_valid(UserSessionState.AUTH0_STD_DONE):
            self.mark_step_failure(
                f"Userdevice ({credential_name}) is not in state auth0 standard done, "
                "either fast transaction was requested or handling auth0 failed"
            )
            return False, None
        self.next_step()

        try:
            cmds_auth1 = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False, None
        try:
            await userdevice.handle_auth1(cmds_auth1)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False, None
        self.next_step()

        while True:
            try:
                command = await userdevice.wait_for_command()
            except InvalidCommandError as error:
                self.mark_step_failure(str(error))
                return False, None

            try:
                if command.ins == INS.SELECT:
                    await userdevice.handle_select(command)
                    self.next_step()
                elif command.ins == INS.ENVELOPE:
                    if not await self._verify_device_request(
                        command.decrypted_payload
                    ):
                        return False, None
                    await userdevice.handle_envelope(command)
                    self.next_step()
                elif command.ins == INS.CONTROL_FLOW:
                    await userdevice.handle_control_flow(command)
                    outcome_description = (
                        f"Step-Up transaction ended with CONTROL FLOW S1 "
                        f"{command.s1.name}"
                    )
                    return True, outcome_description
                elif command.ins == INS.EXCHANGE:
                    await userdevice.handle_exchange(command)
                    self.next_step()
                    reader_status = ReaderStatus(command.reader_status)
                    outcome_description = (
                        f"Step-Up transaction ended with reader status "
                        f"{reader_status.name} (0x{reader_status.value:04x})"
                    )
                    if reader_status.is_success:
                        return False, outcome_description
                    return True, outcome_description
                else:
                    self.mark_step_failure(f"Unexpected command {command.ins}")
                    return False, None
            except AccessProtocolError as error:
                self.mark_step_failure(str(error))
                return False, None

    @log_errors
    async def execute(self) -> None:
        self.next_step()

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in NFC polling mode for "
                f"step-up transaction (validity_iteration={self.accepted_validity_iteration})",
                options={"OK": 1},
            )
        )
        self.next_step()

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Bring Test Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )

        if not await self._do_stepup_transaction(
            self.userdevice,
            f"validity_iteration={self.accepted_validity_iteration}",
        ):
            return

        await self.userdevice.transaction_termination()

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Remove Test Harness from the Reader Device Under Test.\r\n"
                "Set Reader Device Under Test in NFC polling mode for step-up transaction "
                f"(validity_iteration={self.rolled_back_validity_iteration}).\r\n"
                "The rolled back Access Document will be presented.",
                options={"OK": 1},
            )
        )
        self.next_step()

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Bring Test Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )

        self.userdevice = self.rollback_device
        refused, outcome = await self._do_stepup_transaction_expect_refused(
            self.rollback_device,
            f"validity_iteration={self.rolled_back_validity_iteration}",
        )
        if not refused:
            if outcome is not None:
                self.mark_step_failure(
                    "Reader granted access for an Access Document with validity iteration "
                    f"{self.rolled_back_validity_iteration} while AccessIteration is "
                    f"{self.accepted_validity_iteration}. The difference is "
                    f"{self.accepted_validity_iteration - self.rolled_back_validity_iteration}, "
                    "so Aliro v0.9.4 section 7.2.3 makes this Access Document invalid: "
                    f"{outcome}"
                )
            return

        logger.info(
            f"Reader refused the rolled back Access Document as required: {outcome}"
        )

    async def cleanup(self) -> None:
        logger.info(
            "NFC_RDR_NEG_STEPUP_AD_CREDENTIAL_ISSUER_REMOVED Cleanup"
        )
        await self.userdevice.transaction_termination()
        await self.rollback_device.transaction_termination()
