<template>
  <div>
    <button @click="verify">Verify</button>
  </div>
</template>

<script setup>
const data = ref({})

async function verify() {
  try {
    const payload = {
      student_name: "Andrew",
      age: 21,
      address: "Cebu City",
      examinee_no: "EX-2025-001",
      course_taken: "IT",
      date_registered: "2025-07-23",
      birthdate: "2004-06-10"
    }


    data.value = await $fetch(`http://127.0.0.1:8000/register-user`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    })

    console.log("Response from backend:", data.value)
  } catch (error) {
    console.error("Error calling backend:", error)
  }
}
</script>
