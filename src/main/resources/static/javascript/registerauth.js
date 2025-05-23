document.addEventListener("submit", (e) => {
  e.preventDefault();
  const formData = new FormData(e.target);
  fetch('/register', {
    method: 'POST',
    body: formData
  })
    .then(response => {
      console.log("response1: ", response);
      return initialCheckStatus(response)
    })
    .then(credentialCreateJson => {
      console.log("credentialCreateJson: ", credentialCreateJson);
      return {
        publicKey: {
          ...credentialCreateJson.publicKey,
          challenge: base64urlToUint8array(credentialCreateJson.publicKey.challenge),
          user: {
            ...credentialCreateJson.publicKey.user,
            id: base64urlToUint8array(credentialCreateJson.publicKey.user.id),
          },
          excludeCredentials: credentialCreateJson.publicKey.excludeCredentials.map(credential => ({
            ...credential,
            id: base64urlToUint8array(credential.id),
          })),
          extensions: credentialCreateJson.publicKey.extensions,
        },
      };
    })
    .then(credentialCreateOptions => {
      console.log("credentialCreateOptions: ", credentialCreateOptions);
      return navigator.credentials.create(credentialCreateOptions);
    })
    .then(publicKeyCredential => {
      console.log("publicKeyCredential ");
      return {
        type: publicKeyCredential.type,
        id: publicKeyCredential.id,
        response: {
          attestationObject: uint8arrayToBase64url(publicKeyCredential.response.attestationObject),
          clientDataJSON: uint8arrayToBase64url(publicKeyCredential.response.clientDataJSON),
          transports: publicKeyCredential.response.getTransports && publicKeyCredential.response.getTransports() || [],
        },
        clientExtensionResults: publicKeyCredential.getClientExtensionResults(),
      };
    })
    .then((encodedResult) => {
      console.log("encodedResult: ", JSON.stringify(encodedResult));
      const form = document.getElementById("form");
      const formData = new FormData(form);
      console.log("formData: ", formData);
      formData.append("credential", JSON.stringify(encodedResult));
      return fetch("/finishauth", {
        method: 'POST',
        body: formData
      })
    })
    .then((response) => {
      console.log("response2: ", response);
      return followRedirect(response);
    })
    .catch((error) => {
      console.log('Error: ', error);
      return displayError(error);
    });
})