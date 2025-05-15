function checkURL() {
  const url = document.getElementById("urlInput").value;
  const resultElement = document.getElementById("result");

  fetch("http://localhost:5000/check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url }),
  })
  .then(response => response.json())
  .then(data => {
    if (data.malicious) {
      resultElement.textContent = "⚠️ Malicious: " + data.reason;
      resultElement.style.color = "red";
    } else {
      resultElement.textContent = "✅ Safe: " + data.reason;
      resultElement.style.color = "green";
    }
  })
  .catch(error => {
    resultElement.textContent = "Error checking URL.";
    resultElement.style.color = "orange";
  });
}
