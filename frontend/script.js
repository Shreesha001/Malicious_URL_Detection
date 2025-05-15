document.getElementById("checkBtn").addEventListener("click", () => {
  const url = document.getElementById("urlInput").value.trim();
  const resultDiv = document.getElementById("result");
  resultDiv.textContent = "Checking...";
  resultDiv.className = "";

  if (!url) {
    resultDiv.textContent = "Please enter a URL.";
    resultDiv.className = "malicious";
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
        resultDiv.className = "malicious";
      } else {
        resultDiv.textContent = `✅ Safe: ${data.reason}`;
        resultDiv.className = "safe";
      }
    })
    .catch((err) => {
      resultDiv.textContent = "Error checking URL.";
      resultDiv.className = "malicious";
      console.error(err);
    });
});
