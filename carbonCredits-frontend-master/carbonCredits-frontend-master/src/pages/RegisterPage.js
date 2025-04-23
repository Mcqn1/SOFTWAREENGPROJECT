import React, { useState } from 'react';
import axios from '../axios';

const RegisterPage = () => {
  const [form, setForm] = useState({ role: 'employee' });

  const handleChange = e => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleRegister = async () => {
    await axios.post('/auth/register', form);
    alert('Registered! Now login.');
  };

  return (
    <div>
      <h2>Register</h2>
      <input name="fullName" placeholder="Full Name" onChange={handleChange} /><br />
      <input name="email" placeholder="Email" onChange={handleChange} /><br />
      <input name="password" type="password" placeholder="Password" onChange={handleChange} /><br />
      <select name="role" onChange={handleChange}>
        <option value="employee">Employee</option>
        <option value="employer">Employer</option>
      </select><br />
      {form.role === 'employee' && (
        <input name="employerName" placeholder="Employer Name" onChange={handleChange} />
      )}<br />
      <button onClick={handleRegister}>Register</button>
    </div>
  );
};

export default RegisterPage;
