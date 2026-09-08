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
from aliro_actuator.trust_framework.access_credential import AccessCredential
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.access_doc.mdl.common import IssuerNamespaces, DocTypes
from ...support.access_doc.mdl.request import DeviceRequest
from ...support.access_doc.aliro.access import AccessData
from ...support.access_doc.mdl.response.device_response_builder import DeviceResponseBuilder, ResponseElement
from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class NFC_RDR_STEPUP_FAST_KPERSISTENT_REMOVED(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_RDR_STEPUP_FAST_KPERSISTENT_REMOVED",
        "version": "0.0.1",
        "title": "NFC_RDR_STEPUP_FAST_KPERSISTENT_REMOVED",
        "description": """Verify that the Reader removes cached kPersistent keys and Access Documents when the validity iteration difference is greater than or equal to 8, during Step-Up and Expedited-Fast transactions.""",
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

    # Access Credential B keypair
    access_credential_B_PuBK = bytes.fromhex(
        "0400ADBB74BBBB7E06B0A28C7D049B023796CD0F7CB9"
        "E279EC42ECFE6E415842451EB93AC5BF62D25CC1DAEA"
        "898A82B18BD813A061E21CB58B3CA93DA6DC7EC300"
    )
    access_credential_B_PrivK = bytes.fromhex(
        "63BD7CE2A4ED2C35232E2C642851F3E22E6F274E1F164CA3B4D32CCA18B51FFE"
    )

    VALIDITY_ITERATION_REMOVAL_THRESHOLD = 8
    VALIDITY_ITERATION_A1 = 1
    VALIDITY_ITERATION_B = (
        VALIDITY_ITERATION_A1 + VALIDITY_ITERATION_REMOVAL_THRESHOLD
    )  # Difference from A1 is exactly 8
    VALIDITY_ITERATION_A2 = VALIDITY_ITERATION_B + 1

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "RD",
                "NFC",
                "RD11",
                "RD24",
                "RD28",
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Initialization"),
            TestStep("Step2: Set Reader Device Under Test in polling mode"),
            TestStep("Step3: Transaction Initiation Step-Up (Credential A)"),
            TestStep("Step4: Receive/Send AUTH0 command/response Step-Up (Credential A)"),
            TestStep("Step5: Receive/Send AUTH1 command/response Step-Up (Credential A)"),
            TestStep("Step6: Handle Step-up SELECT (Credential A)"),
            TestStep("Step7: Handle ENVELOPE command/response (Credential A)"),
            TestStep("Step8: Handle EXCHANGE command/response Step-Up (Credential A)"),
            TestStep("Step9: Transaction Initiation Fast (Credential A)"),
            TestStep("Step10: Receive/Send AUTH0 command/response Fast (Credential A)"),
            TestStep("Step11: Receive/Send EXCHANGE command/response Fast (Credential A)"),
            TestStep("Step12: Transaction Initiation Step-Up (Credential B)"),
            TestStep("Step13: Receive/Send AUTH0 command/response Step-Up (Credential B)"),
            TestStep("Step14: Receive/Send AUTH1 command/response Step-Up (Credential B)"),
            TestStep("Step15: Handle Step-up SELECT (Credential B)"),
            TestStep("Step16: Handle ENVELOPE command/response (Credential B)"),
            TestStep("Step17: Handle EXCHANGE command/response Step-Up (Credential B)"),
            TestStep("Step18: Transaction Initiation Step-Up (Credential A - document A1 rejected)"),
            TestStep("Step19: Receive/Send AUTH0 command/response (Credential A - document A1 rejected)"),
            TestStep("Step20: Receive/Send AUTH1 command/response Standard (Credential A - document A1 rejected)"),
            TestStep("Step21: Handle Step-up SELECT (Credential A - document A1 rejected)"),
            TestStep("Step22: Handle ENVELOPE command/response (Credential A - document A1 rejected)"),
            TestStep("Step23: Handle EXCHANGE/CONTROL FLOW (Credential A - document A1 rejected)"),
            TestStep("Step24: Transaction Initiation (Credential A - kPersistent removed)"),
            TestStep("Step25: Receive/Send AUTH0 command/response Fast (Credential A - kPersistent removed)"),
            TestStep("Step26: Receive/Send AUTH1 command/response Standard (Credential A - kPersistent removed)"),
            TestStep("Step27: Handle Step-up SELECT (Credential A - kPersistent removed)"),
            TestStep("Step28: Handle ENVELOPE command/response (Credential A - kPersistent removed)"),
            TestStep("Step29: Receive/Send EXCHANGE command/response Standard (Credential A - kPersistent removed)"),
            TestStep("Step30: Transaction Initiation Fast (Credential A - kPersistent restored)"),
            TestStep("Step31: Receive/Send AUTH0 command/response Fast (Credential A - kPersistent restored)"),
            TestStep("Step32: Receive/Send EXCHANGE command/response Fast (Credential A - kPersistent restored)"),
            TestStep("Step33: Transaction Initiation Fast (Credential B)"),
            TestStep("Step34: Receive/Send AUTH0 command/response Fast (Credential B)"),
            TestStep("Step35: Receive/Send EXCHANGE command/response Fast (Credential B)"),
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
            data_elements=[ResponseElement(data_element_id=self.element_id, value=access_element)],
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

    async def setup(self) -> None:
        logger.info("This is a test case setup")

        signed_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=3)

        self.access_credential_A = self.reader_access_credential(use_random_ud_keypair=True)

        self.access_doc_A1 = self.build_access_document(
            self.access_credential_A.get_access_credential_public_key().as_bytes(),
            self.VALIDITY_ITERATION_A1,
            signed_time=signed_time,
        )

        access_credential_B = AccessCredential(
            access_credential_key_pair=KeyPair(
                self.access_credential_B_PrivK, self.access_credential_B_PuBK
            ),
            reader_id_key_list=self.access_credential_A.reader_id_key_list,
        )

        access_doc_B = self.build_access_document(
            access_credential_B.get_access_credential_public_key().as_bytes(),
            self.VALIDITY_ITERATION_B,
            signed_time=signed_time,
        )

        self.access_doc_A2 = self.build_access_document(
            self.access_credential_A.get_access_credential_public_key().as_bytes(),
            self.VALIDITY_ITERATION_A2,
            signed_time=signed_time,
        )

        self.userdevice_A = UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[self.access_credential_A],
            mailbox=0x20,
            ephemeral_key_list=[
                KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK),
                KeyPair(self.endpoint_ePrivK_2, self.endpoint_ePuBK_2),
            ],
            access_document=self.access_doc_A1,
            step_up_aid_required=True,
        )

        self.userdevice_B = UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[access_credential_B],
            mailbox=0x20,
            ephemeral_key_list=[
                KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK),
                KeyPair(self.endpoint_ePrivK_2, self.endpoint_ePuBK_2),
            ],
            access_document=access_doc_B,
            step_up_aid_required=True,
        )

        self.userdevice = self.userdevice_A

    async def _do_stepup_transaction(self, userdevice: UserDevice, credential_name: str) -> bool:
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
                f"Userdevice ({credential_name}) is not in state auth0 standard done, either fast "
                "transaction was requested or handling auth0 failed"
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

        device_request = DeviceRequest()
        if not device_request.from_cbor(cmds_envelope.decrypted_payload):
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
            self.mark_step_failure(f"Reader did not request Element ID {self.element_id}")
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
            self.mark_step_failure(f"Reader did not request Element ID {self.element_id}")
            return False

        return True

    async def _do_stepup_transaction_expect_refused(
        self,
        userdevice: UserDevice,
        credential_name: str,
        validity_iteration: int,
        reader_access_iteration: int,
    ) -> bool:
        """Perform a Step-Up transaction and expect access to be refused."""
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

        auth0_fast_done = userdevice.session.state_valid(UserSessionState.AUTH0_FAST_DONE)
        auth0_std_done = userdevice.session.state_valid(UserSessionState.AUTH0_STD_DONE)
        if not auth0_fast_done and not auth0_std_done:
            self.mark_step_failure(
                f"Userdevice ({credential_name}) is not in state auth0 fast done or "
                "auth0 standard done after handling AUTH0"
            )
            return False
        self.next_step()

        try:
            cmds_auth1 = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False

        if auth0_fast_done and cmds_auth1.ins != INS.AUTH1:
            self.mark_step_failure(
                f"Expected AUTH1 command after fast AUTH0 because Reader removed kPersistent, "
                f"but received {cmds_auth1.ins}"
            )
            return False

        if cmds_auth1.ins != INS.AUTH1:
            self.mark_step_failure(
                f"Expected AUTH1 command during step-up transaction, but received {cmds_auth1.ins}"
            )
            return False

        try:
            await userdevice.handle_auth1(cmds_auth1)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False
        self.next_step()

        while True:
            try:
                command = await userdevice.wait_for_command()
            except InvalidCommandError as error:
                self.mark_step_failure(str(error))
                return False

            try:
                if command.ins == INS.SELECT:
                    await userdevice.handle_select(command)
                    self.next_step()
                elif command.ins == INS.ENVELOPE:
                    if not await self._verify_device_request(command.decrypted_payload):
                        return False
                    await userdevice.handle_envelope(command)
                    self.next_step()
                elif command.ins == INS.CONTROL_FLOW:
                    await userdevice.handle_control_flow(command)
                    logger.info(
                        f"Reader refused Access Document for {credential_name} "
                        f"(validity_iteration={validity_iteration}) with CONTROL FLOW "
                        f"S1 {command.s1.name}"
                    )
                    self.next_step()
                    return True
                elif command.ins == INS.EXCHANGE:
                    await userdevice.handle_exchange(command)
                    self.next_step()
                    reader_status = ReaderStatus(command.reader_status)
                    if reader_status.is_success:
                        self.mark_step_failure(
                            f"Reader granted access for Access Document with validity "
                            f"iteration {validity_iteration} while AccessIteration is "
                            f"{reader_access_iteration}. The difference is "
                            f"{reader_access_iteration - validity_iteration}, so Aliro "
                            f"v0.9.4 section 7.2.3 makes this Access Document invalid: "
                            f"{reader_status.name} (0x{reader_status.value:04x})"
                        )
                        return False
                    logger.info(
                        f"Reader refused Access Document for {credential_name} "
                        f"(validity_iteration={validity_iteration}) with reader status "
                        f"{reader_status.name} (0x{reader_status.value:04x})"
                    )
                    return True
                else:
                    self.mark_step_failure(f"Unexpected command {command.ins}")
                    return False
            except AccessProtocolError as error:
                self.mark_step_failure(str(error))
                return False

    async def _do_fast_transaction(self, userdevice: UserDevice, credential_name: str) -> bool:
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
        if not userdevice.session.state_valid(UserSessionState.AUTH0_FAST_DONE):
            self.mark_step_failure(
                f"Userdevice ({credential_name}) is not in state auth0 fast done, either standard "
                "transaction was requested or handling auth0 failed"
            )
            return False
        self.next_step()

        while True:
            try:
                cmds_exchange = await userdevice.wait_for_command()
            except InvalidCommandError as error:
                self.mark_step_failure(str(error))
                return False

            if cmds_exchange.ins == INS.EXCHANGE:
                try:
                    await userdevice.handle_exchange(cmds_exchange)
                except AccessProtocolError as error:
                    self.mark_step_failure(str(error))
                    return False

                if userdevice.session.state_valid(UserSessionState.TRANSACTION_COMPLETE):
                    if not ReaderStatus(cmds_exchange.reader_status).is_success:
                        self.mark_step_failure(
                            "Expected Success Reader Status (0x01..), but received {}".format(
                                cmds_exchange.reader_status.name
                            )
                        )
                        return False
                    break
            else:
                self.mark_step_failure(f"Unexpected command {cmds_exchange.ins}")
                return False

        self.next_step()
        return True

    async def _do_fast_to_standard_fallback_with_stepup_transaction(
        self,
        userdevice: UserDevice,
        credential_name: str,
        reader_access_iteration: int,
        removed_credential_validity_iteration: int,
    ) -> bool:
        """
        Verify the Reader removed kPersistent / Access Document for this Access Credential
        after a validity iteration difference >= 8 by forcing Standard Step-Up.
        """
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

        if not userdevice.session.state_valid(UserSessionState.AUTH0_FAST_DONE):
            self.mark_step_failure(
                f"Userdevice ({credential_name}) is not in state auth0 fast done. "
                "Expected fast capability due to existing kPersistent."
            )
            return False
        self.next_step()

        try:
            cmds_auth1 = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False

        if cmds_auth1.ins != INS.AUTH1:
            self.mark_step_failure(
                f"Expected AUTH1 command because Reader removed kPersistent / Access Document "
                f"for {credential_name} after validity iteration difference "
                f"{reader_access_iteration - removed_credential_validity_iteration} "
                f"(AccessIteration={reader_access_iteration}, cached="
                f"{removed_credential_validity_iteration}), "
                f"but received {cmds_auth1.ins}"
            )
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

        device_request = DeviceRequest()
        if not device_request.from_cbor(cmds_envelope.decrypted_payload):
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
            self.mark_step_failure(f"Reader did not request Element ID {self.element_id}")
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

        if cmds_exchange.ins == INS.EXCHANGE:
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
        else:
            self.mark_step_failure(f"Expected EXCHANGE command, but received {cmds_exchange.ins}")
            return False

        self.next_step()
        return True

    @log_errors
    async def execute(self) -> None:
        self.next_step()

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in NFC polling mode for "
                "step-up transaction (Credential A)",
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
        self.userdevice = self.userdevice_A
        if not await self._do_stepup_transaction(self.userdevice_A, "Credential A"):
            return

        await self.userdevice_A.transaction_termination()
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Remove Test Harness, set Reader Device Under Test in "
                "NFC polling mode for fast transaction (Credential A), \r\nand bring Test "
                "Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )

        if not await self._do_fast_transaction(self.userdevice_A, "Credential A"):
            return

        await self.userdevice_A.transaction_termination()
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Remove Test Harness, set Reader Device Under Test in "
                f"NFC polling mode for step-up transaction (Credential B, "
                f"validity_iteration={self.VALIDITY_ITERATION_B}), \r\nand bring Test "
                "Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )

        self.userdevice = self.userdevice_B
        if not await self._do_stepup_transaction(self.userdevice_B, "Credential B"):
            return

        await self.userdevice_B.transaction_termination()

        self.userdevice_A.access_document = self.access_doc_A1

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Remove Test Harness, set Reader Device Under Test in "
                f"NFC polling mode for step-up transaction (Credential A, "
                f"validity_iteration={self.VALIDITY_ITERATION_A1}).\r\n"
                "The previously accepted Access Document A1 must be rejected because "
                f"AccessIteration is now {self.VALIDITY_ITERATION_B}.\r\n"
                "Bring Test Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )

        self.userdevice = self.userdevice_A
        if not await self._do_stepup_transaction_expect_refused(
            self.userdevice_A,
            "Credential A",
            validity_iteration=self.VALIDITY_ITERATION_A1,
            reader_access_iteration=self.VALIDITY_ITERATION_B,
        ):
            return

        await self.userdevice_A.transaction_termination()
        self.userdevice_A.access_document = self.access_doc_A2

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Remove Test Harness, set Reader Device Under Test in "
                f"NFC polling mode for transaction (Credential A, "
                f"validity_iteration={self.VALIDITY_ITERATION_A2}).\r\n"
                "Reader should have removed Credential A kPersistent / Access Document "
                f"after Credential B step-up (difference "
                f"{self.VALIDITY_ITERATION_B - self.VALIDITY_ITERATION_A1} "
                f">= {self.VALIDITY_ITERATION_REMOVAL_THRESHOLD}).\r\n"
                "Bring Test Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )

        self.userdevice = self.userdevice_A
        if not await self._do_fast_to_standard_fallback_with_stepup_transaction(
            self.userdevice_A,
            "Credential A",
            reader_access_iteration=self.VALIDITY_ITERATION_B,
            removed_credential_validity_iteration=self.VALIDITY_ITERATION_A1,
        ):
            return

        await self.userdevice_A.transaction_termination()
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Remove Test Harness, set Reader Device Under Test in "
                f"NFC polling mode for fast transaction (Credential A, "
                f"validity_iteration={self.VALIDITY_ITERATION_A2}).\r\n"
                "Confirm Credential A kPersistent works again after the step-up transaction.\r\n"
                "Bring Test Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )

        self.userdevice = self.userdevice_A
        if not await self._do_fast_transaction(self.userdevice_A, "Credential A"):
            return

        await self.userdevice_A.transaction_termination()
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Remove Test Harness, set Reader Device Under Test in "
                "NFC polling mode for fast transaction (Credential B), \r\nand bring Test "
                "Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )

        self.userdevice = self.userdevice_B
        if not await self._do_fast_transaction(self.userdevice_B, "Credential B"):
            return

    async def cleanup(self) -> None:
        logger.info("NFC_RDR_STEPUP_FAST_KPERSISTENT_REMOVED Cleanup")
        await self.userdevice.transaction_termination()
