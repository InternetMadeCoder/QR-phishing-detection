"use client";

import { useState, useEffect, useRef } from "react";
import axios from "axios";
import QRScanner from "../components/QRScanner";

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ||
  (typeof window !== "undefined"
    ? `http://${window.location.hostname === "localhost" ? "127.0.0.1" : window.location.hostname}:5000`
    : "http://127.0.0.1:5000");

export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState("");
  const [showPopup, setShowPopup] = useState(false);
  const popupTimeout = useRef(null);

  const checkUrl = async () => {
    const trimmedUrl = url.trim();
    if (!trimmedUrl) {
      setResult("Please enter a URL before checking.");
      setShowPopup(true);
      clearTimeout(popupTimeout.current);
      popupTimeout.current = setTimeout(() => setShowPopup(false), 10000);
      return;
    }

    try {
      const res = await axios.post(`${API_BASE}/predict`, {
        url: trimmedUrl,
      });
      const successData = res.data;
      const successText = `${successData.result}${successData.reason ? ` — ${successData.reason}` : ""}`;
      setResult(successText);
      setShowPopup(true);
      clearTimeout(popupTimeout.current);
      popupTimeout.current = setTimeout(() => setShowPopup(false), 10000);
    } catch (err) {
      const errorData = err.response?.data;
      if (errorData?.result) {
        const errorText = `${errorData.result}${errorData.reason ? ` — ${errorData.reason}` : ""}`;
        setResult(errorText);
      } else {
        setResult(
          `Network error: unable to reach the backend at ${API_BASE}. ${
            err.message || "Please verify the Flask server is running."
          }`,
        );
      }
      setShowPopup(true);
      clearTimeout(popupTimeout.current);
      popupTimeout.current = setTimeout(() => setShowPopup(false), 10000);
      console.error(err);
    }
  };

  // Popup color logic
  let popupColor = "bg-gray-300 text-black";
  if (/safe/i.test(result)) popupColor = "bg-green-500 text-white";
  else if (/phish/i.test(result)) popupColor = "bg-red-500 text-white";

  return (
    <main className="min-h-screen bg-gray-100 flex items-center justify-center text-black">
      <div className="bg-white/80 backdrop-blur-xl p-8 rounded-2xl shadow-2xl w-[420px] text-center text-black">
        <h1 className="text-2xl font-semibold mb-4">QR Phishing Detector</h1>

        <input
          type="text"
          placeholder="Enter or scan URL..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="w-full p-3 rounded-xl border mb-4 outline-none"
        />

        <button
          onClick={checkUrl}
          disabled={!url.trim()}
          className={`w-full bg-black text-white py-2 rounded-xl hover:opacity-80 ${
            !url.trim() ? "opacity-50 cursor-not-allowed" : ""
          }`}
        >
          Check URL
        </button>

        {/* QR Scanner */}
        <div className="mt-6 border rounded-xl p-3 bg-gray-50">
          <QRScanner setUrl={setUrl} />
        </div>

        {/* Result Popup */}
        {showPopup && result && (
          <div
            className={`fixed left-1/2 top-8 -translate-x-1/2 z-50 px-6 py-4 rounded-xl shadow-xl text-lg font-semibold transition-all duration-300 ${popupColor}`}
            style={{ minWidth: 220 }}
          >
            {result}
          </div>
        )}
      </div>
    </main>
  );
}
