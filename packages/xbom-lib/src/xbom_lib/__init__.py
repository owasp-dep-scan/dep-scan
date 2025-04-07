from abc import ABC, abstractmethod
from logging import Logger
from typing import Optional, Dict, Any

from dataclasses import dataclass


@dataclass
class BOMResult:
    """
    Data class representing the result of BOM generation.
    """

    success: bool = False
    command_output: Optional[str] = None
    bom_obj: Optional[Any] = None


class XBOMGenerator(ABC):
    """
    Base class for generating xBOM (Bill of Materials).

    Attributes:
        source_dir (str): Directory containing source files.
        bom_file (str): Output BOM file path.
        logger (Optional[logger]): Logger object
        options (Optional[Dict[str, Any]]): Additional options for generation.
    """

    def __init__(
        self,
        source_dir: str,
        bom_file: str,
        logger: Optional[Logger] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the xBOMGenerator.

        Args:
            source_dir (str): The source directory.
            bom_file (str): The BOM file path.
            logger ():
            options (Optional[Dict[str, Any]]): Additional generation options.
        """
        self.source_dir = source_dir
        self.bom_file = bom_file
        self.logger = logger
        self.options = options if options is not None else {}

    @abstractmethod
    def generate(self) -> BOMResult:
        """
        Generate the BOM.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method.")
