document.getElementById("checkBtn").addEventListener("click", () => {
  const url = document.getElementById("urlInput").value.trim();
  const resultDiv = document.getElementById("result");
  resultDiv.textContent = "Checking...";
  resultDiv.className = "result"; // Reset to base class

  if (!url) {
    resultDiv.textContent = "Please enter a URL.";
    resultDiv.className = "result malicious";
    return;
  }

  fetch("http://127.0.0.1:5000/check", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  })
    .then((res) => res.json())
    .then((data) => {
      if (data.malicious) {
        resultDiv.textContent = `⚠️ Malicious: ${data.reason}`;
        resultDiv.className = "result malicious";
      } else {
        resultDiv.textContent = `✅ Safe: ${data.reason}`;
        resultDiv.className = "result safe";
      }
    })
    .catch((err) => {
      resultDiv.textContent = "Error checking URL.";
      resultDiv.className = "result malicious";
      console.error(err);
    });
});