from lsassy.logger import lsassy_logger
from lsassy.output import IOutput


class Output(IOutput):
    """
    Return output in pretty colorful format
    """

    def get_output(self) -> str:
        """
        Retrieve and format the credentials information in a readable and aligned manner.

        Returns:
            str: A string representing the formatted output containing the credentials information.
                If no credentials are found, it returns a message indicating so.
        """
        # Step 1: Initialize an empty list to store the final output.
        output = []

        # Step 2: Check if credentials are available.
        if not self._credentials or len(self._credentials) == 0:
            return "No credentials found."

        # Step 3: Calculate the maximum size for padding.
        # This ensures proper alignment in the output.
        max_size = max(
            len(c.get("hostname") or "")
            + len(c.get("domain") or "")
            + len(c.get("username") or "")
            for c in self._credentials
            if c is not None
        )

        # Step 4: Initialize a list to store unique credentials.
        credentials = []

        # Step 5: Iterate over each credential and format the output.
        for cred in self._credentials:
            if cred is None:
                continue

            # Step 5.1: Determine the credential type (e.g., PWD, TGT, etc.).
            cred_type, password = self._determine_cred_type_and_password(cred)

            # Step 5.2: Check for uniqueness and append to credentials list.
            if [
                cred.get("domain"),
                cred.get("username"),
                password,
            ] not in credentials:
                credentials.append([cred.get("domain"), cred.get("username"), password])

                # Step 5.3: Format the output line and append to the output list.
                output_line = self._format_output_line(
                    cred, cred_type, password, max_size
                )
                output.append(output_line)

        # Step 6: Join and return the final output.
        return "\n".join(output)

    def _determine_cred_type_and_password(self, cred: dict) -> tuple[str, str]:
        """
        Determine the credential type and password based on the information provided.

        Args:
            cred (dict): A dictionary containing credential information such as password, ticket, masterkey, etc.

        Returns:
            tuple[str, str]: A tuple containing two strings: the credential type (e.g., "PWD", "TGT", "DPAPI Masterkey", "NT") and the corresponding password or credential data.
        """
        cred_type = "PWD"
        password = cred.get("password")

        if password is None:
            if cred.get("ticket") is not None:
                password = "Domain: {} - End time: {} ({})".format(
                    cred["ticket"]["domain"],
                    cred["ticket"]["endtime"].strftime("%Y-%m-%d %H:%M"),
                    cred["ticket"]["file"],
                )
                cred_type = "TGT"
            elif cred.get("masterkey") is not None:
                password = "{}".format(cred["masterkey"])
                cred_type = "DPAPI Masterkey"
            else:
                password = ":".join(
                    h for h in [cred.get("lmhash"), cred.get("nthash")] if h is not None
                )
                cred_type = "NT"

        return cred_type, password

    def _format_output_line(
        self, cred: dict, cred_type: str, password: str, max_size: int
    ) -> str:
        """
        Format a single line of output with proper padding and highlighting.

        Args:
            cred (dict): A dictionary containing credential information such as domain, username, password, etc.
            cred_type (str): A string indicating the type of credential (e.g., "PWD", "TGT", "DPAPI Masterkey", "NT").
            password (str): A string representing the password or relevant credential data.
            max_size (int): An integer representing the maximum length required for padding to align the output.

        Returns:
            str: A formatted string representing a single line of the output.
        """
        hostname = cred.get("hostname") or ""
        domain = "{}\\".format(cred.get("domain")) if cred.get("domain") else " "
        username = cred.get("username") or ""
        padding = " " * (max_size - len(domain) - len(username) + 2)
        sha1_info = (
            " | {}".format(
                lsassy_logger.lsassy_highlight(
                    "[{}] {}".format("SHA1", cred.get("sha1"))
                )
            )
            if cred.get("sha1")
            else ""
        )

        output_line = "{} - {}{}{}{}{}{}".format(
            hostname,
            domain,
            username,
            padding,
            lsassy_logger.lsassy_highlight("[{}] ".format(cred_type)),
            lsassy_logger.lsassy_highlight(password),
            sha1_info,
        )

        return output_line
