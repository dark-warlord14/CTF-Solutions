
# Imaginary Notes (100pts) - by cleverbear57

## Description

No code is provided.  

![Challenge Overview](image.png)

From the description, it feels like the challenge will be using the Supabase JS SDK. But let’s see what unfolds.

---

## First Look

![Landing Page](image-1.png)

**After signing up:**  

![Signed Up](image-2.png)

**After adding a test note:**  

![Added Note](image-3.png)

---

## Traffic Analysis

Let’s check the traffic in Burp:  

![Burp Traffic](image-4.png)

This confirms the usage of **Supabase**.  

Supabase REST API makes it very easy to perform DB operations. But an important part is getting the **RLS (Row-Level Security)** right.  
Anonymous keys need to be embedded in the frontend, since the REST API won’t work without them.

![Supabase API Call](image-5.png)

The Supabase API call shows that `users` is the database. Let’s see if we can interact with it.

![DB Query](image-6.png)

And we can. Since everything is plain text, we have the flag as the **password for the admin user**. 🎯

![Flag Found](image-7.png)

---
