import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# Dữ liệu mẫu
data = [
    {"ctr": 1.2, "cr": 2.8, "cpp": 18.0, "roi": 12.0, "fee_ads": 25.0, "action": "Cần tối ưu hóa nội dung quảng cáo. Hãy thêm từ khóa cụ thể và cải thiện hình ảnh."},
    {"ctr": 0.8, "cr": 1.5, "cpp": 22.5, "roi": 8.5, "fee_ads": 35.0, "action": "Giảm phí quảng cáo bằng cách chọn từ khóa mục tiêu tốt hơn. Tăng chất lượng trang đích để cải thiện CR."},
    {"ctr": 3.0, "cr": 5.0, "cpp": 10.0, "roi": 25.0, "fee_ads": 15.0, "action": "Chiến dịch đang hoạt động tốt. Hãy tăng ngân sách để mở rộng phạm vi tiếp cận."},
    {"ctr": 1.0, "cr": 2.0, "cpp": 20.0, "roi": 10.0, "fee_ads": 30.0, "action": "Cần đánh giá lại chiến dịch. Hãy kiểm tra nội dung quảng cáo và tối ưu hóa từ khóa để cải thiện CTR và CR."}
]

# Chuyển dữ liệu thành DataFrame
df = pd.DataFrame(data)

# Xác định X và y
X = df.drop(columns=["action"])
y = df["action"]

# Khởi tạo mô hình
model = RandomForestClassifier()
model.fit(X, y)

# Hàm xử lý logic đề xuất chi tiết
def get_detailed_recommendation(ctr, cr, cpp, fee_ads, roi):
    recommendations = []

    # ✅ Logic cho CTR
    if ctr == 0:
        recommendations.append("""
           <strong>CTR bằng 0%.</strong> <br> 
            CTR đang rất thấp (không tốt) so với ngưỡng trung bình của thị trường. Hãy xem lại toàn diện như: giá, hình ảnh sản phẩm, Khuyến mãi, tiêu đề, mô tả sản phẩm và chính sách ship hàng. <br> Và tự kiểm tra lại các vấn đề sau:
            1/ Giá cả hợp lý chưa? Có đặt giá cao quá không? Nếu có hãy kiểm tra giá cả và hạ giá xuống.<br>
            2/ Hình ảnh, video sản phẩm có đẹp bằng hoặc hơn đối thủ chưa? Nếu chưa hãy cải thiện nó tốt hơn.<br>
            3/ Tiêu đề, từ khoá sản phẩm đã tối ưu chưa? Nếu chưa, hãy rà soát lại từ khoá đảm bảo điền đúng theo niche đang bán.<br>
            4/ Chọn lựa từ khoá phù hợp để phân phối quảng cáo, tối ưu SEO đến đúng đối tượng mua hàng.<br>
            5/ Nên có các chương trình khuyến mãi hấp dẫn người mua thì họ mới click vào. Ví dụ, giảm giá 40-50% hay free ship...""")

    elif 1 <= ctr < 2.5:
        recommendations.append("""
	<strong>CTR đang hơi thấp </strong><br>
	 CTR chưa tốt so với mức ngưỡng trung bình của thị trường. Cố gắng tìm cách tăng tỉ lệ Click lên cao hơn để có cơ hội bán được nhiều hàng hơn. Tập trung vào các điểm chính như Giá cả, Chính sách ship hàng click vào. """)
    elif 2.5 <= ctr < 3.5:
        recommendations.append("""
	<strong> CTR đang ở mức bình thường </strong><br>
	CTR của bạn đang gần với ngưỡng trung bình của thị trường. Nhìn chung cũng khá khả quan, nhưng hãy cố gắng duy trì và tìm cách tăng tỉ lệ Click lên cao hơn để có cơ hội bán được nhiều hàng hơn. Ví dụ, bạn có thể tập trung vào các điểm chính thu hút khách hàng nhiều hơn nữa như để tăng lượt click thêm như như đặt Giá cạnh tranh hơn,  tối ưu chính sách ship hàng, chạy chương trình khuyến mãi nhiều hơn. """)
    elif ctr >= 3.5:
        recommendations.append("""
	<strong> CTR đang ở mức cao (tốt) </strong><br>
        CTR của bạn đang cao hơn so với mức ngưỡng trung bình thị trường. Chức mừng! Bạn đang làm tốt, hãy cố gắng duy trì tỉ lệ này luôn mở mức cao nhé. <br>
	Tuy nhiên, cần theo dõi thêm các chỉ số khác như CR, CPP và Fee ads để xem với tỉ lệ click đang tốt thì có chuyển đổi thành đơn hàng nhiều không?  Và chi phí quảng cáo bỏ ra để có order có cao không (CPP)? Nếu có click nhiều thì phải có order, đảm bảo chi phí quảng cáo và lợi nhuận  ở mức ngưỡng phù hợp. """)

    # ✅ Logic cho CR
    if cr < 2:
        recommendations.append("""
	<strong> CR đang thấp. </strong><br> 
	Xem xét tối ưu lại cửa hàng toàn diện. Kiểm tra lại giá, hình ảnh, chương trình khuyến mãi, chính sách vận chuyễn đã làm tốt chưa? Giá bạn đặt có quá cao so với thị trường? Bạn có đang chạy khuyến mãi giảm giá trên cửa hàng của mình không? <br>
	Ví dụ: thử chạy giảm giá từ 30 đến 50%, áp dụng nhiều chính sách khuyến mại trong vài tháng xem có cải thiện CR lên không?Tuy nhiên, hãy lưu ý là nếu mẫu mã sản phẩm, thiết kế sản phẩm không đẹp và không đúng nhu cầu thị trường thì dù bạn có giảm giá vẫn có thể khó kéo CR lên nhanh. Hãy nhớ nghiên cứu ngách bán, tìm idea thật tố và đăng sản phẩm đều đặn mỗi ngàyt.<br>
	Ngoài ra, cửa hàng mới sẽ bán chậm hơn, có tỷ lệ CR kém hơn các cửa hàng lâu năm, do độ trust của cửa hàng chưa cao, bạn hãy kiên nhẫn và cải thiện các vấn đề nêu trên thật tốt, từ từ, tỷ lệ CR sẽ cao hơn. Có thể sau 6 tháng, hoặc 1 năm bán hàng trở lên... """)
    elif 2 <= cr < 4:
        recommendations.append("""
	<strong> CR ở mức trung bình. </strong><br> 
	CR đang ở mức trunh bình, bạn hãy cải thiện thêm chút nữa để tăng tỷ lệ chuyển đổi lên thêm. <br>
 	Ví dụ: thử chạy giảm giá từ 30 đến 50%, áp dụng nhiều chính sách khuyến mại trong vài tháng xem có cải thiện CR lên không?Tuy nhiên, hãy lưu ý là nếu mẫu mã sản phẩm, thiết kế sản phẩm không đẹp và không đúng nhu cầu thị trường thì dù bạn có giảm giá vẫn có thể khó kéo CR lên nhanh. Hãy nhớ nghiên cứu ngách bán, tìm idea thật tốt và đăng sản phẩm đều đặn mỗi ngày <br>
	Ngoài ra, cửa hàng mới sẽ bán chậm hơn, có tỷ lệ CR kém hơn các cửa hàng lâu năm, do độ trust của cửa hàng chưa cao, bạn hãy kiên nhẫn và cải thiện các vấn đề nêu trên thật tốt, từ từ, tỷ lệ CR sẽ cao hơn. Có thể sau 6 tháng, hoặc 1 năm bán hàng trở lên... """)
    elif cr >= 4:
        recommendations.append("""
	<strong> CR đang cao. </strong><br> 
	CR của bạn đang cao, hãy tiếp tục duy trì chiến lược hiện tại và tìm cách tăng ngân sách quảng cáo nếu chỉ số quảng cáo khác đang phân phối tốt như CTR, CPP, Fee ads """)


    # ✅ Logic cho CPP
    if cpp == 0:
        recommendations.append("""
         <strong>CPP thấp (đang làm tốt).</strong><br>
         Tuỳ vào lợi nhuận (profit margin) của sản phẩm là bao nhiêu thì mới đánh giá đúng bản chất CPP của bạn là tốt hay không?<br>
 	Trường hợp này, tôi giả sử bạn đang bán Shirt, nên tự đặt giả thuyết là bán 1 cái t-shirt, bạn sẽ lời 12USD. Dựa trên giả thuyết này, CPP bạn đang ở thấp ( hiểu là đang làm tốt). Vì nếu bán 1 sản phẩm lời 12USD, nhưng CPP (chi phí tiền quảng cáo để có 1 order) đang dưới 12usd, nghĩa là bạn đang làm tốt. <br>
	Hãy cố gắng duy trì CPP ở mức thấp nhất có thể, làm sao để CPP luôb thấp hơn lợi nhuận của sản phẩm đang bán. <br>
	Ví dụ, bạn bán 1 cái nón lời 10usd, thì CPP nên từ 10usd trở xuống""")

    elif 12 <= cpp < 14:
        recommendations.append("""
	<strong> CPP ở mức bình thường.</strong><br>
	 Tuỳ vào lợi nhuận (profit margin) của sản phẩm là bao nhiêu thì mới đánh giá đúng bản chất CPP của bạn là tốt hay không? <br>
	 Trường hợp này,  tôi giả sử bạn đang bán Shirt, nên tự đặt giả thuyết là bán 1 cái t-shirt, bạn sẽ lời 12USD. Dựa trên giả thuyết này, CPP bạn đang ở mức bình thường. Vì nếu bán 1 sản phẩm lời 12USD, nhưng CPP (chi phí tiền quảng cáo để có 1 order) đang hơn 12usd một ít, nghĩa là tiền quảng cáo gần hoà vốn hoặc lời ít với tiền profit nhận được.  <br>
	Hãy cố gắng duy trì CPP ở mức thấp nhất có thể, CPP nên thấp hơn profit của sản phẩm. <br>
	Ví dụ, bạn bán 1 cái nón lời 10usd, thì CPP nên duy trì dưới 10usd. """)

    elif cpp >= 14:
        recommendations.append("""
<strong> CPP đang cao. </strong><br> Tuỳ vào profit margin của sản phẩm đang bán là gì thì mới biết CPP là tốt hay không? Trường hợp này, chủ tool giả sử bạn đang bán Shirt, nên giả thuyết bán 1 cái shirt sẽ lời 12USD. Dựa trên giả thuyết trên, CPP bạn đang ở mức cao. Vì nếu bán 1 sản phẩm lời 12USD, nhưng CPP (chi phí tiền quảng cáo để có 1 order) đang lớn hơn 14usd, nghĩa là tiền quảng cáo để có 1 order cao tiền profit của 1 order. Hãy cố gắng kéo CPP ở mức thấp nhất có thể, CPP nên thấp hơn profit của sản phẩm.
Ví dụ, bạn bán 1 cái nón lời 10usd, thì CPP nên từ 10usd trở xuống """)

    # ✅ Logic cho Fee Ads
    if fee_ads < 20:
        recommendations.append("""
	<strong> Chi phí Fee ads đang thấp. </strong><br>
	Chi phí quảng cáo của bạn đang thấp hơn ngưỡng trung bình. <br>
	Tuỳ chi phí fullfil đơn hàng, chi phí khác của bạn là bao nhiêu % so với doanh thu mà bạn mới xác  định được chi phí Fee ads phù hợp. Giả bạn đang bán POD, và chi phí Fullfil khoảng 50% doanh thu.<br>
	 Dựa trên giả thuyết trên, chi phí Fee ads đang thấp (làm tốt), phí càng thấp là càng tốt. Hãy cố gắng duy trì chi phí marketing ở mức thấp so với doanh thu, để có profit bán hàng phù hợp""")

    elif 20 <= fee_ads < 23:
        recommendations.append("""
	<strong> Chi phí Fee ads đang bình thương. </strong><br>
	Chi phí quảng cáo của bạn đang gần ngang ngưỡng trung bình. <br>
	Tuỳ chi phí fullfil đơn hàng, chi phí khác của bạn là bao nhiêu % so với doanh thu mà bạn mới xác  định được chi phí Fee ads phù hợp. Giả bạn đang bán POD, và chi phí Fullfil khoảng 50% doanh thu. <br>
	Dựa trên giả thuyết trên, chi phí Fee ads đang bình thường. Với cửa hàng bán trên 6 tháng, nên theo dõi ads sát sao hơn mỗi ngày, để điều chỉnh ngân sách quảng cáo kịp thời cố gắng duy trì chi phí marketing ở mức phù hợp so với doanh thu (dưới 23%), bạn mới có lợi nhuận. Với cửa hàng mới bán dưới 3 tháng, hãy chịu khó duy trì quảng cáo dài thêm, thậm chí chấp nhận lỗ ít các tháng đầu. Nên chạy ads với ngân sách vừa nhỏ (từ 1-5usd), chấp nhận Fee ads cao hơn mức cho phép thông thường 1 chút để có cơ hội tiếp cận khách hàng nhiều hơn.""")

    elif fee_ads >= 23:
        recommendations.append("""
	<strong> Chi phí Fee ads đang cao. </strong><br>
 	Chi phí quảng cáo của bạn đang cao hơn ngưỡng trung bình. <br>
	Tuỳ chi phí fullfil đơn hàng, chi phí khác của bạn là bao nhiêu % so với doanh thu mà bạn mới xác  định được chi phí Fee ads phù hợp. Giả bạn đang bán POD, và chi phí Fullfil khoảng 50% doanh thu. <br>
	Dựa trên giả thuyết trên, chi phí Fee ads đang cao. Với cửa hàng bán trên 6 tháng, nên theo dõi ads sát sao mỗi ngày, để điều chỉnh ngân sách quảng cáo kịp thời cố gắng duy trì chi phí marketing ở mức phù hợp so với doanh thu (dưới 23%), bạn mới có lợi nhuận. Nếu đang chạy ads liên tục trên 2 tuần mà Fee ads đang cao hơn 23%, bạn cần kiểm tra ngân sách ads đang bao nhiêu 1 ngày, nếu rủi ro chi phí tăng đột biến cao nên giảm ngân sách ads xuống để tối ưu lại cửa hàng của mình, kiểm tra lại sản phẩm, giá cả...<br>
	Với cửa hàng mới bán dưới 3 tháng, hãy chịu khó duy trì quảng cáo dài thêm, thậm chí chấp nhận lỗ ít các tháng đầu. Nên chạy ads với ngân sách vừa nhỏ (từ 1-5usd), chấp nhận Fee ads cao hơn mức cho phép thông thường 1 chút để có cơ hội tiếp cận khách hàng nhiều hơn. Tuy nhiên, nếu đã chạy ads lâu, và thấy vấn đề vượt kiểm soát, chi phí có thể tăng đột biến thì tạm thời có thể giảm ngân sách ads xuống để giảm chi phí ads ngay. """)


    if roi <= 0.01:
        recommendations.append("""
	<strong> ROI đang thấp. </strong><br>
	ROI đang thấp (chưa tốt). Nghĩa là khoản đầu tư quảng cáo này, chưa sinh lời như kỳ vọng, doanh thu chưa tương xứng tiền đầu tư. Nhưng bạn hãy khoan điều chỉnh, mà nên kiểm tra lại các chỉ số CTR, CR, CPP và Fee ads, bạn sẽ có cái nhìn chi tiết hơn và biết mình nên làm gì trước. <br>
	Về lý thuyết, ROI càng cao là càng tốt! Tuy nhiên, nên xem thời gian đầu tư là bao lâu nữa? Ví dụ, bạn đầu tư 100usd tiền ads trong 1 ngày, bán được 2 orders tương ứng doanh thu 200usd, ROI sẽ là 100% trong 1 ngày. Nhưng nếu phải mất 1 tuần chạy ads là 100usd, mới bán được 200usd thì dù ROI vẫn 100%, nhưng thời gian sinh lời lâu hơn.""")

    elif roi < 75:
        recommendations.append("""
	<strong> ROI đang thấp. </strong><br>
	Chỉ số ROI đang thấp (chưa tốt). Nghĩa là khoản đầu tư quảng cáo này, chưa sinh lời như kỳ vọng, doanh thu chưa tương xứng tiền đầu tư. Nhưng bạn hãy khoan điều chỉnh, mà nên kiểm tra lại các chỉ số CTR, CR, CPP và Fee ads, bạn sẽ có cái nhìn chi tiết hơn và biết mình nên làm gì trước. <br>
	Về lý thuyết, ROI càng cao là càng tốt! Tuy nhiên, nên xem thời gian đầu tư là bao lâu nữa? Ví dụ, bạn đầu tư 100usd tiền ads trong 1 ngày, bán được 2 orders tương ứng doanh thu 200usd, ROI sẽ là 100% trong 1 ngày. Nhưng nếu phải mất 1 tuần chạy ads là 100usd, mới bán được 200usd thì dù ROI vẫn 100%, nhưng thời gian sinh lời lâu hơn.""")

    elif 75 <= roi < 100:
        recommendations.append("""
	<strong> ROI đang mức bình thường. </strong><br>
	 Chỉ số ROI đang bình thường. Nghĩa là khoản đầu tư quảng cáo này bình thường, chưa sinh lời cao. Nhưng bạn hãy khoan điều chỉnh, mà nên kiểm tra lại các chỉ số CTR, CR, CPP và Fee ads, bạn sẽ có cái nhìn chi tiết hơn và biết mình nên làm gì trước.<br>
	Về lý thuyết, ROI càng cao là càng tốt! Tuy nhiên, nên xem thời gian đầu tư là bao lâu nữa? Ví dụ, bạn đầu tư 100usd tiền ads trong 1 ngày, bán được 2 orders tương ứng doanh thu 200usd, ROI sẽ là 100% trong 1 ngày. Nhưng nếu phải mất 1 tuần chạy ads là 100usd, mới bán được 200usd thì dù ROI vẫn 100%, nhưng thời gian sinh lời lâu hơn.""")

    elif roi >= 100:
        recommendations.append("""
	<strong> ROI đang mức cao. </strong><br> 
	Chỉ số ROI của bạn đang tốt. Nghĩa là khoản đầu tư quảng cáo đang sinh lời cao. Nhưng bạn hãy khoan quá vui mừng, mà nên kiểm tra lại các chỉ số CTR, CR, CPP và Fee ads, bạn sẽ có cái nhìn chi tiết hơn và tổng thể hơn.<br>
	Về lý thuyết, ROI càng cao là càng tốt! Tuy nhiên, nên xem thời gian đầu tư là bao lâu? Bạn nên xem xét tổng thể nhiều chỉ số, nhiều góc nhìn khác nhau và cần tính thực tế hàng tháng đang lời bao nhiêu tiền? <br>
	Từ đó, điều chỉnh cách làm cho phù hợp. Nếu ROI đang tốt, các chỉ số khác có tốt không? ROI tốt là tốt trong khoảng thời gian nào? làm sao để duy trì và làm cho ROI tốt hơn torng tương lai...? Đó là các câu hỏi bạn cần tìm câu trả lời thông qua rà soát lại các chỉ số CTR, CR, CPP, Fee ads, net Profit...<br>
Ví dụ, bạn đầu tư 100usd tiền ads trong 1 ngày, bán được 2 orders tương ứng doanh thu 200usd, ROI sẽ là 100% trong 1 ngày. Nhưng nếu phải mất 1 tuần chạy ads là 100usd, mới bán được 200usd thì dù ROI vẫn 100%, nhưng thời gian sinh lời lâu hơn.""")


    # ✅ Trả về đề xuất với mỗi câu xuống hàng
    return "<br>".join(recommendations)


# Hàm dự đoán hành động
def predict_action(input_data):
    # Chuyển đổi dữ liệu đầu vào thành DataFrame để giữ tên cột
    import pandas as pd
    input_df = pd.DataFrame([input_data])

    # Dự đoán
    prediction = model.predict(input_df)
    action = prediction[0]

    # Kết hợp đề xuất hành động chi tiết
    recommendations = get_detailed_recommendation(
        ctr=input_data.get("ctr", 0),
        cr=input_data.get("cr", 0),
        cpp=input_data.get("cpp", 0),
        fee_ads=input_data.get("fee_ads", 0),
        roi=input_data.get("roi", 0)
    )

    return f"{action}. {recommendations}"

# Ví dụ dự đoán
example = {"ctr": 0.0, "cr": 0.0, "cpp": 0.0, "roi": 0.0, "fee_ads": 0.0}
print(predict_action(example))
