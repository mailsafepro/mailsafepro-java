export API_URL="http://localhost:8000/validate/email"
export BATCH_URL="http://localhost:8000/validate/batch"
export PREMIUM_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2ZWYyZDRhOC1jM2VkLTQzOTktYTJiZC0zMGM1NzIxNjIyY2IiLCJlbWFpbCI6InBhYmxvYWd1ZG8wMUB5YWhvby5jb20iLCJleHAiOjE3NjM0MDkxMTksImlhdCI6MTc2MzQwODIxOSwibmJmIjoxNzYzNDA4MjE5LCJqdGkiOiI1MTFhOTM0OC03ZTcwLTRkYmUtYTliNy01Yjc5ZTM2MDZlMzMiLCJpc3MiOiJlbWFpbC1hcGkiLCJhdWQiOiJlbWFpbC1jbGllbnRzIiwic2NvcGVzIjpbInZhbGlkYXRlOnNpbmdsZSIsInZhbGlkYXRlOmJhdGNoIiwiYmF0Y2g6dXBsb2FkIiwiYmlsbGluZyIsImpvYjpjcmVhdGUiLCJqb2I6cmVhZCIsImpvYjpyZXN1bHRzIiwid2ViaG9vazptYW5hZ2UiXSwicGxhbiI6IlBSRU1JVU0iLCJ0eXBlIjoiYWNjZXNzIn0.HK1ftxZX6zZ-LPPcK4SXSRplLWjjdIH_RHBFcgKU3ZM"

echo "TEST 145: Batch con duplicados (deduplicar)"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test@gmail.com", "test@gmail.com", "test@gmail.com"], "check_smtp": false}' | jq '.'
echo ""

echo "TEST 146: Batch PREMIUM 50 emails"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test0@gmail.com","test1@gmail.com","test2@gmail.com","test3@gmail.com","test4@gmail.com","test5@gmail.com","test6@gmail.com","test7@gmail.com","test8@gmail.com","test9@gmail.com","test10@gmail.com","test11@gmail.com","test12@gmail.com","test13@gmail.com","test14@gmail.com","test15@gmail.com","test16@gmail.com","test17@gmail.com","test18@gmail.com","test19@gmail.com","test20@gmail.com","test21@gmail.com","test22@gmail.com","test23@gmail.com","test24@gmail.com","test25@gmail.com","test26@gmail.com","test27@gmail.com","test28@gmail.com","test29@gmail.com","test30@gmail.com","test31@gmail.com","test32@gmail.com","test33@gmail.com","test34@gmail.com","test35@gmail.com","test36@gmail.com","test37@gmail.com","test38@gmail.com","test39@gmail.com","test40@gmail.com","test41@gmail.com","test42@gmail.com","test43@gmail.com","test44@gmail.com","test45@gmail.com","test46@gmail.com","test47@gmail.com","test48@gmail.com","test49@gmail.com"], "check_smtp": false}' | jq '.'
echo ""

echo "TEST 147: Batch con check_smtp=true"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test1@gmail.com", "test2@example.org"], "check_smtp": true}' | jq '.'
echo ""

echo "TEST 148: Batch con include_raw_dns"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test1@gmail.com", "test2@gmail.com"], "check_smtp": false, "include_raw_dns": true}' | jq '.'
echo ""

echo "TEST 149: Batch límite FREE (100 emails)"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test0@gmail.com","test1@gmail.com","test2@gmail.com","test3@gmail.com","test4@gmail.com","test5@gmail.com","test6@gmail.com","test7@gmail.com","test8@gmail.com","test9@gmail.com","test10@gmail.com","test11@gmail.com","test12@gmail.com","test13@gmail.com","test14@gmail.com","test15@gmail.com","test16@gmail.com","test17@gmail.com","test18@gmail.com","test19@gmail.com","test20@gmail.com","test21@gmail.com","test22@gmail.com","test23@gmail.com","test24@gmail.com","test25@gmail.com","test26@gmail.com","test27@gmail.com","test28@gmail.com","test29@gmail.com","test30@gmail.com","test31@gmail.com","test32@gmail.com","test33@gmail.com","test34@gmail.com","test35@gmail.com","test36@gmail.com","test37@gmail.com","test38@gmail.com","test39@gmail.com","test40@gmail.com","test41@gmail.com","test42@gmail.com","test43@gmail.com","test44@gmail.com","test45@gmail.com","test46@gmail.com","test47@gmail.com","test48@gmail.com","test49@gmail.com","test50@gmail.com","test51@gmail.com","test52@gmail.com","test53@gmail.com","test54@gmail.com","test55@gmail.com","test56@gmail.com","test57@gmail.com","test58@gmail.com","test59@gmail.com","test60@gmail.com","test61@gmail.com","test62@gmail.com","test63@gmail.com","test64@gmail.com","test65@gmail.com","test66@gmail.com","test67@gmail.com","test68@gmail.com","test69@gmail.com","test70@gmail.com","test71@gmail.com","test72@gmail.com","test73@gmail.com","test74@gmail.com","test75@gmail.com","test76@gmail.com","test77@gmail.com","test78@gmail.com","test79@gmail.com","test80@gmail.com","test81@gmail.com","test82@gmail.com","test83@gmail.com","test84@gmail.com","test85@gmail.com","test86@gmail.com","test87@gmail.com","test88@gmail.com","test89@gmail.com","test90@gmail.com","test91@gmail.com","test92@gmail.com","test93@gmail.com","test94@gmail.com","test95@gmail.com","test96@gmail.com","test97@gmail.com","test98@gmail.com","test99@gmail.com"], "check_smtp": false}' | jq '.'
echo ""

echo "TEST 150: Batch excede límite FREE (>100)"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test0@gmail.com","test1@gmail.com","test2@gmail.com","test3@gmail.com","test4@gmail.com","test5@gmail.com","test6@gmail.com","test7@gmail.com","test8@gmail.com","test9@gmail.com","test10@gmail.com","test11@gmail.com","test12@gmail.com","test13@gmail.com","test14@gmail.com","test15@gmail.com","test16@gmail.com","test17@gmail.com","test18@gmail.com","test19@gmail.com","test20@gmail.com","test21@gmail.com","test22@gmail.com","test23@gmail.com","test24@gmail.com","test25@gmail.com","test26@gmail.com","test27@gmail.com","test28@gmail.com","test29@gmail.com","test30@gmail.com","test31@gmail.com","test32@gmail.com","test33@gmail.com","test34@gmail.com","test35@gmail.com","test36@gmail.com","test37@gmail.com","test38@gmail.com","test39@gmail.com","test40@gmail.com","test41@gmail.com","test42@gmail.com","test43@gmail.com","test44@gmail.com","test45@gmail.com","test46@gmail.com","test47@gmail.com","test48@gmail.com","test49@gmail.com","test50@gmail.com","test51@gmail.com","test52@gmail.com","test53@gmail.com","test54@gmail.com","test55@gmail.com","test56@gmail.com","test57@gmail.com","test58@gmail.com","test59@gmail.com","test60@gmail.com","test61@gmail.com","test62@gmail.com","test63@gmail.com","test64@gmail.com","test65@gmail.com","test66@gmail.com","test67@gmail.com","test68@gmail.com","test69@gmail.com","test70@gmail.com","test71@gmail.com","test72@gmail.com","test73@gmail.com","test74@gmail.com","test75@gmail.com","test76@gmail.com","test77@gmail.com","test78@gmail.com","test79@gmail.com","test80@gmail.com","test81@gmail.com","test82@gmail.com","test83@gmail.com","test84@gmail.com","test85@gmail.com","test86@gmail.com","test87@gmail.com","test88@gmail.com","test89@gmail.com","test90@gmail.com","test91@gmail.com","test92@gmail.com","test93@gmail.com","test94@gmail.com","test95@gmail.com","test96@gmail.com","test97@gmail.com","test98@gmail.com","test99@gmail.com","test100@gmail.com","test101@gmail.com","test102@gmail.com","test103@gmail.com","test104@gmail.com","test105@gmail.com","test106@gmail.com","test107@gmail.com","test108@gmail.com","test109@gmail.com","test110@gmail.com","test111@gmail.com","test112@gmail.com","test113@gmail.com","test114@gmail.com","test115@gmail.com","test116@gmail.com","test117@gmail.com","test118@gmail.com","test119@gmail.com","test120@gmail.com","test121@gmail.com","test122@gmail.com","test123@gmail.com","test124@gmail.com","test125@gmail.com","test126@gmail.com","test127@gmail.com","test128@gmail.com","test129@gmail.com","test130@gmail.com","test131@gmail.com","test132@gmail.com","test133@gmail.com","test134@gmail.com","test135@gmail.com","test136@gmail.com","test137@gmail.com","test138@gmail.com","test139@gmail.com","test140@gmail.com","test141@gmail.com","test142@gmail.com","test143@gmail.com","test144@gmail.com","test145@gmail.com","test146@gmail.com","test147@gmail.com","test148@gmail.com","test149@gmail.com"], "check_smtp": false}' | jq '.'
echo ""

echo "TEST 151: Batch con errores parciales"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["valid@gmail.com", "", "invalid@", "test@example.com"], "check_smtp": false}' | jq '.'
echo ""

echo "TEST 152: Batch timeout individual"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test@gmail.com", "test@slow-domain.test", "test@yahoo.com"], "check_smtp": false}' | jq '.'
echo ""

echo "TEST 153: Batch respuesta array completo"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test1@gmail.com", "test2@gmail.com"], "check_smtp": false}' | jq '.'
echo ""