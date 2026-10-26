"""Builds tests/data/labeled_messages.json (synthetic examples written for testing).
Add real (redacted) examples over time: AARP, FTC and your own users' reports are good sources."""
import json, pathlib

scams = [
 ("irs_gift_card", "This is the IRS. You owe back taxes and a warrant has been issued for your arrest. Pay immediately with gift cards or you will be arrested today."),
 ("ssa_suspended", "Social Security Administration: your number has been suspended due to suspicious activity. Call 1-888-555-0142 now to avoid legal action."),
 ("grandson_jail", "Grandma it's me, I'm in jail after a car accident. I need bail money. Please don't tell mom and dad. Send $2,000 today."),
 ("new_number", "Hi Mom, I dropped my phone in the lake, this is my new number. Can you text me back? I need help paying a bill."),
 ("amazon_charge", "Amazon: you were charged $499.99 for an iPhone order. If you did not make this purchase call 1-855-555-0188 to dispute the charge."),
 ("ms_virus", "WARNING: Virus detected! Your computer is infected. Do not shut down. Call Microsoft support at 1-800-555-0123 immediately."),
 ("usps_fee", "USPS: your package could not be delivered. Pay the unpaid redelivery fee here: bit.ly/3xYzAb"),
 ("toll_text", "E-ZPass: you have an outstanding toll balance of $12.40. Pay now to avoid a late fee: https://e-zpass-billing.top/pay"),
 ("safe_account", "This is your bank's fraud department. Hackers are in your account. For your protection, move your savings to a safe account we will set up for you."),
 ("investment", "Join our crypto trading group. Guaranteed returns of 40% per month, risk-free. Message me to start."),
 ("wrong_number", "Hi, sorry, I think I texted the wrong number. Do we know each other? You seem very kind."),
 ("romance", "My love, I am deployed overseas and cannot video call. I need you to send $1,500 so I can come home to you."),
 ("lottery", "Congratulations! You have won the national sweepstakes. Pay the processing fee of $250 to claim your prize."),
 ("utility", "Your electric power will be disconnected today unless you pay your balance within 2 hours. Call to pay now."),
 ("remote", "Please install AnyDesk so I can connect to your computer and fix the problem with your account."),
 ("medicare", "Medicare: your new card is ready. Confirm your Medicare number and date of birth to avoid your benefits expiring."),
 ("recovery", "We can recover your lost bitcoin investment. A small recovery fee is required to begin."),
 ("job_check", "Work from home job offer! We will send you a check to cash. Buy the equipment and send back the rest."),
 ("overpayment", "We accidentally sent you too much. Please send back the difference by Zelle immediately."),
 ("paypal_lookalike", "PayPal: your account has been limited. Verify your account at https://paypal-secure-login.xyz/verify"),
 ("otp_request", "I'm from your bank. We sent you a code by text. Please read me the verification code to confirm your identity."),
 ("geek_squad", "Geek Squad: your subscription has been renewed for $349.99. To cancel and get a refund call 1-844-555-0177."),
 ("boss_gift_cards", "I'm in a meeting and need you to buy gift cards for clients today. Keep this between us and send me the codes."),
 ("bank_locked", "Chase alert: your account is locked due to unusual activity. Verify your account at http://chase-secure-login.top now."),
 ("l33t", "Y0u have been selected! Buy g1ft cards and read me the numbers to claim your pr1ze."),
 ("ip_link", "Your account is suspended. Click the link to verify your identity: http://192.168.44.12/login"),
]

legit = [
 ("pharmacy", "CVS Pharmacy: Your prescription is ready for pickup at your usual store."),
 ("bank_fraud_alert", "Chase fraud alert: Did you attempt a $48.20 purchase at Walmart? Reply YES or NO. We will never ask for your password or full card number."),
 ("otp", "Your verification code is 482913. Do not share this code with anyone."),
 ("amazon_delivered", "Amazon: your package was delivered to your front door."),
 ("usps_out", "USPS: your package is out for delivery today."),
 ("grandma_pickup", "Hi Grandma, can you pick me up from practice at 5? Mom is at work."),
 ("son_hospital", "My son is in the hospital for a minor surgery, please keep him in your prayers."),
 ("utility_bill", "Duke Energy: your bill of $112.40 is due Nov 3. Pay online or call the number on your statement."),
 ("appointment", "Please confirm your appointment with Dr. Lee on Nov 4 by replying YES."),
 ("statement", "Your October statement is ready. Log in to the official app to view it."),
 ("medicare_notice", "Medicare: your Medicare Summary Notice is available online at https://www.medicare.gov."),
 ("family_dinner", "Dinner at 6 on Sunday, bring the pie. Love, Mom"),
 ("zelle_sent", "Your Zelle payment of $50 to Sarah was sent."),
 ("fedex_sched", "FedEx: your delivery is scheduled for tomorrow between 10am and 2pm."),
 ("refill", "Walgreens: refill reminder for your blood pressure prescription."),
 ("bank_warning", "Wells Fargo: we will never call or text to ask for your PIN or one-time code. If someone does, hang up."),
 ("new_baby", "Congratulations on the new baby! We are so happy for you both."),
 ("donation", "Thank you for your donation of $50 to First Baptist Church."),
 ("bingo", "I won the bingo game last night! Want to come on Saturday?"),
 ("ssa_letter", "Social Security Administration: your cost-of-living adjustment letter is available in your my Social Security account at https://www.ssa.gov."),
 ("neighbor", "Hi, it's your neighbor. I'm at the hospital with my husband, can you feed the cat tonight?"),
 ("card_back", "Please call the number on the back of your card if you did not make this purchase."),
 ("netflix_renew", "Your Netflix subscription has been renewed for $15.49."),
 ("wont_come", "I won't be able to make it Thursday, can we do Friday instead?"),
 ("gift_birthday", "Thanks for the gift card, Grandma! I used it to get a new book."),
 ("verify_appt", "Can you send me the address for the party on Saturday?"),
]

# Second batch: written after the first round of tuning, to check the rules generalize.
scams += [
 ("apple_id_lock", "Your Apple ID has been locked. Sign in at apple-id-support.click to restore access."),
 ("norton_renew", "Dear customer, your Norton subscription auto-renewed for $399. Call 1-866-555-0100 for a refund."),
 ("grandpa_mexico", "Hello Grandpa, I'm in trouble, got into an accident in Mexico. Please wire money to my lawyer and don't tell Dad."),
 ("medicare_final", "Final notice: Medicare benefits will be suspended unless you verify your information today."),
 ("ssn_stimulus", "Pls send ur SSN and bank account number so we can deposit your stimulus payment."),
 ("refund_842", "You are eligible for a refund of $842. Reply with your bank account number to receive it."),
 ("sheriff_bitcoin", "I am Sgt. Miller with the sheriff's office. There is a warrant for you for missing jury duty. Pay a fine at once with bitcoin."),
 ("ai_trading", "Invest with our AI trading platform, 3% daily profit, can't lose. Join on WhatsApp."),
 ("remote_virus", "Your computer has a virus. Allow remote access so our technician can remove it."),
 ("pch_prize", "Congratulations, your Publishers Clearing House prize of $2.5M is ready. Send a $300 release fee."),
 ("dad_new_phone", "Text from Dad: new phone, who dis? Need you to pay a bill for me, will pay you back."),
 ("netflix_vip", "Netflix: payment failed. Update your card at netflix-billing.vip/update."),
]
legit += [
 ("airport_pickup", "Hi Grandpa, we land at 3pm Friday. Can you pick us up at the airport?"),
 ("kroger_points", "Kroger: your fuel points expire Nov 30. Use them at the pump."),
 ("bank_stmt_sept", "Your bank statement for September is ready. Sign in to your account at the official website to view it."),
 ("flu_shot", "Reminder: your flu shot appointment is tomorrow at 10am at Walgreens."),
 ("lyft", "Your Lyft ride is arriving in 3 minutes."),
 ("verizon_bill", "Verizon: your bill of $87.12 is ready. Autopay will draft on Nov 5."),
 ("bike_accident", "My daughter had an accident on her bike but she's fine. Thanks for the casserole!"),
 ("irs_received", "IRS: Your tax return was received and is being processed. Check status at irs.gov/refunds."),
 ("citi_otp", "Citibank: Your one-time code is 774412. Never share this code with anyone, including Citi employees."),
 ("church_roof", "The church will hold a fundraiser to raise money for the new roof. Please send any donations by check to the office."),
]

rows = [{"id": i, "label": "scam", "text": t} for i, t in scams] + [{"id": i, "label": "legit", "text": t} for i, t in legit]
pathlib.Path(__file__).with_name("labeled_messages.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False))
print(len(scams), "scam,", len(legit), "legit")
