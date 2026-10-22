from harbor_helper.common import write_outputs
from support import TemporaryTestCase


class OutputTests(TemporaryTestCase):
    def test_outputs_reject_newlines(self) -> None:
        self.assert_workflow_error(
            "contains a newline",
            write_outputs,
            {"value": "safe\nunsafe=value"},
            self.root / "output",
        )
