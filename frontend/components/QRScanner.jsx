"use client";

import { useEffect } from "react";
import { Html5QrcodeScanner } from "html5-qrcode";

const QRScanner = ({ setUrl }) => {
  useEffect(() => {
    const scanner = new Html5QrcodeScanner(
      "reader",
      { fps: 10, qrbox: 250 },
      false
    );

    scanner.render(
      (decodedText) => {
        setUrl(decodedText);
        scanner.clear();
      },
      () => {}
    );

    return () => scanner.clear().catch(() => {});
  }, [setUrl]);

  return <div id="reader" className="mt-4"></div>;
};

export default QRScanner;