<jsp:include page="../../base.jsp"></jsp:include>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/copytest.css" />
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/table.css" />

<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/jquery.min.js"></script>
<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/dataTables/jquery.dataTables.min.js"></script>
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/jquery.dataTables.min.css">

		<div class="mcontent">
			<div class="titlenav">
				<ul>
					<li class="title"><a href="">Transaction Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Order
							Management > Transaction List > Transaction Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Transaction ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.transaction_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Purchase ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.purchase_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Purchase Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.purchase_type}" /></td>
				<td Class ="FormCellColor" colspan="2"></td>
				<td Class ="FormInputColor" colspan="2"></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">DateTime</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.date_time}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${transactionMain.date_time}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Owner ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.owner_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Owner Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.owner_name}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Mobile</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.mobile}" /></td>
				<td Class ="FormCellColor" colspan="2">Needed Date</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.needed_date_time}" /></td>
				<td Class ="FormCellColor" colspan="2">From Account</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.from_account_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">To Account</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.to_account_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Company ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.company_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Company Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.company_name}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Total Amount</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.total_amount}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.order_status == 'P' ? 'Pending' : transactionMain.order_status == 'A' ? 'Approved' : transactionMain.order_status == 'C' ? 'Cancel' : transactionMain.order_status == 'S' ? 'Success' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Delivery Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.delivery_status == 'P' ? 'Pending' : transactionMain.delivery_status == 'D' ? 'Delivered' : transactionMain.delivery_status == 'C' ? 'Cancel' : transactionMain.delivery_status == 'S' ? 'Success' : transactionMain.delivery_status == 'R' ? 'Return' : ''}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Reason</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.reason}" /></td>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.created}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${transactionMain.created}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.updated}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${transactionMain.updated}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.created_by}" /></td>
				<td Class ="FormCellColor" colspan="2">Updated By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${transactionMain.updated_by}" /></td>
			</tr>
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<a Class ="button" href="${pageContext.request.contextPath}/TransactionMainController?action=transactionProductListEnquiry&transaction_id=${transactionMain.transaction_id}&purchase_id=${transactionMain.purchase_id}&date_time=${transactionMain.date_time}&owner_name=${transactionMain.owner_name}&mobile=${transactionMain.mobile}">Product Enquiry</a>
						<a Class ="button" href="${pageContext.request.contextPath}/jsp/order/transactionMain.jsp">Return</a></td>
					</td>
				</tr>
		</table>
	</form>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->

	<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

</body>
</html>