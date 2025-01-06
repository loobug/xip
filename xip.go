package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

const (
	invalidIPFormat       = "无效的 IP 地址格式，请重试。"
	invalidSubnetFormat   = "无效的子网掩码格式，请重试。"
	invalidPrefixFormat   = "无效的前缀长度，请输入 0 到 128 之间的数字。"
	invalidIPv6Format     = "无效的 IPv6 地址格式，请重试。"
	invalidOption         = "无效的选项，请输入合适的数字范围。"
	invalidInterface      = "无效的接口，请输入 lan、wlan 或s(选择)。"
	adapterNotFound       = "未找到网络适配器 '%s'。"
	configuringDHCP       = "正在配置 DHCP..."
	configuringStaticIP   = "正在配置静态 IP..."
	dhcpSuccess           = "%s DHCP 配置成功"
	staticIPSuccess       = "%s 静态 IP 配置成功"
	addIPSuccess          = "%s 添加 %s 成功"
	removeIPSuccess       = "%s 移除 %s 成功"
	configuringStaticIPv6 = "正在配置静态 IPv6..."
	dhcpv6Success         = "%s DHCPv6 配置成功"
	addIPv6Success        = "%s 添加 IPv6 %s 成功"
	removeIPv6Success     = "%s 移除 IPv6 %s 成功"

	currentConfig      = "\n当前配置:"
	availableOptions   = "\n可用选项:"
	networkToolTitle   = "网络配置工具 by @cc"
	networkToolDivLine = "================================="
)

var (
	ipv4Regex       = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	subnetMaskRegex = regexp.MustCompile(`^\d+$`)
	ipv6Regex       = regexp.MustCompile(`^[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,7}$`)
	reader          = bufio.NewReader(os.Stdin) // 全局的 bufio.Reader
	yellowColor     = color.New(color.FgYellow)
	defaultColor    = color.New(color.FgHiCyan)
	redColor        = color.New(color.FgRed)
	exitString      = "exit"
)

// decodeGBK 将 GBK 编码的字节切片转换为 UTF-8 字符串
func decodeGBK(data []byte) (string, error) {
	decoder := simplifiedchinese.GBK.NewDecoder()
	reader := transform.NewReader(strings.NewReader(string(data)), decoder)
	output, err := bufio.NewReader(reader).ReadString('\x00')
	if err != nil && err.Error() != "EOF" {
		return "", err
	}
	return output, nil
}

// Helper function to test IPv4 address
func testIPAddress(ip string) bool {
	if !ipv4Regex.MatchString(ip) {
		return false
	}

	parts := strings.Split(ip, ".")
	for _, part := range parts {
		val, err := strconv.Atoi(part)
		if err != nil || val < 0 || val > 255 {
			return false
		}
	}
	return true
}

// Helper function to convert subnet mask
func convertSubnetMask(mask string) (string, bool) {
	if ipv4Regex.MatchString(mask) {
		return mask, true
	}
	if subnetMaskRegex.MatchString(mask) {
		subnetBits, err := strconv.Atoi(mask)
		if err != nil || subnetBits < 0 || subnetBits > 32 {
			return "", false
		}
		result := make([]string, 0)
		for i := 0; i < 4; i++ {
			if subnetBits >= 8 {
				result = append(result, "255")
				subnetBits -= 8
			} else {
				maskVal := (1<<subnetBits - 1) << (8 - subnetBits)
				result = append(result, strconv.Itoa(maskVal))
				subnetBits = 0
			}
		}
		return strings.Join(result, "."), true
	}
	return "", false
}

// Helper function to test IPv6 address
func testIPv6Address(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	if addr.To4() != nil {
		return false
	}
	return true
}

// Helper function to convert subnet prefix for IPv6
func convertSubnetPrefix(mask string) (string, bool) {
	if ipv6Regex.MatchString(mask) {
		ip := net.ParseIP(mask)
		if ip == nil {
			return "", false
		}
		bits := 0
		for _, b := range ip.To16() {
			for i := 7; i >= 0; i-- {
				if (b>>uint(i))&1 == 0 {
					break
				}
				bits++
			}
		}

		prefixLength := bits
		return fmt.Sprintf("/%d", prefixLength), true
	} else if matched, _ := regexp.MatchString(`^\d+$`, mask); matched {
		prefix, err := strconv.Atoi(mask)
		if err != nil || prefix < 0 || prefix > 128 {
			return "", false
		}
		return fmt.Sprintf("/%d", prefix), true
	}
	return "", false
}

// Helper function to get valid input
func getValidv6Input(prompt string, validValues []string, errorMessage string) string {
	for {
		defaultColor.Printf(prompt + ": ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		for _, v := range validValues {
			if v == input {
				return input
			}
		}
		redColor.Println(errorMessage)
	}
}

// 获取用户输入并验证
func getValidInput(prompt string, validInputs []string, invalidMsg string, signalChan chan os.Signal) (string, bool) {
	reader := bufio.NewReader(os.Stdin)
	for {
		select {
		case <-signalChan:
			return "", true // return true  when ctrl+c
		default:
			defaultColor.Print(prompt + ": ")
			input, err := reader.ReadString('\n')
			if err != nil {
				continue // avoid panic when signal receive
			}
			input = strings.TrimSpace(input)

			if input == exitString {
				os.Exit(0)
			}
			for _, valid := range validInputs {
				if input == valid {
					return input, false // return false when input is valid
				}
			}
			redColor.Println(invalidMsg)
		}

	}

}

func getValidIPInput(prompt string, errorMessage string, signalChan chan os.Signal) (string, bool) {
	if errorMessage == "" {
		errorMessage = invalidIPFormat
	}
	for {
		select {
		case <-signalChan:
			return "", true
		default:
			defaultColor.Printf(prompt + ": ")
			input, err := reader.ReadString('\n')
			if err != nil {
				continue
			}
			input = strings.TrimSpace(input)
			if testIPAddress(input) {
				return input, false
			}
			redColor.Println(errorMessage)
		}
	}
}

// Helper function to get valid IPv6 input
func getValidIPv6Input(prompt string, errorMessage string, signalChan chan os.Signal) (string, bool) {
	if errorMessage == "" {
		errorMessage = invalidIPv6Format
	}
	for {
		select {
		case <-signalChan:
			return "", true
		default:
			defaultColor.Printf(prompt + ": ")
			input, err := reader.ReadString('\n')
			if err != nil {
				continue
			}
			input = strings.TrimSpace(input)

			if testIPv6Address(input) {
				return input, false
			}
			redColor.Println(errorMessage)
		}
	}
}

// Helper function to get valid subnet mask
func getValidNetmask(prompt string, signalChan chan os.Signal) (string, bool) {
	if prompt == "" {
		prompt = "设置子网掩码 (例如: 255.255.255.0 或 24)"
	}
	for {
		select {
		case <-signalChan:
			return "", true
		default:
			defaultColor.Printf(prompt + ": ")
			input, err := reader.ReadString('\n')
			if err != nil {
				continue
			}
			input = strings.TrimSpace(input)
			mask, valid := convertSubnetMask(input)
			if valid {
				return mask, false
			}
			redColor.Println(invalidSubnetFormat)
		}
	}
}

func executeNetshCommand(args ...string) ([]byte, error) {
	cmd := exec.Command("netsh", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		redColor.Printf("执行 netsh 命令失败: %s \n %s", err.Error(), string(output))
		return nil, err
	}

	return output, nil
}

// Helper function to set DHCP configuration
func setDHCPConfiguration(iface string) {
	yellowColor.Println(configuringDHCP)
	output, err := exec.Command("netsh", "interface", "ip", "set", "address", "name="+iface, "source=dhcp").CombinedOutput()
	if err != nil {
		redColor.Println("设置 DHCP 配置时出错:")
		redColor.Println(decodeGBK(output))
		return
	}

	output, err = exec.Command("netsh", "interface", "ip", "set", "dns", "name="+iface, "source=dhcp").CombinedOutput()
	if err != nil {
		redColor.Println("设置 DHCP DNS 配置时出错:")
		redColor.Println(decodeGBK(output))
		return
	}

	fmt.Printf(dhcpSuccess, iface)
}

func setDHCPIPv6Configuration(iface string) {
	yellowColor.Println("正在配置 DHCPv6...")
	log.Printf("Start configuring DHCPv6 for interface: %s\n", iface)

	outputipv6, err := exec.Command("netsh", "interface", "ipv6", "show", "address", fmt.Sprintf("interface=%s", iface)).CombinedOutput()
	if err != nil {
		log.Printf("获取接口 %s 的 IPv6 地址时出错: %v\n", iface, err)
		return
	}
	re := regexp.MustCompile(`Address\s*([\da-fA-F:]+)\s+Parameters`)
	matches := re.FindAllStringSubmatch(string(outputipv6), -1)
	var ipv6Addrs []string
	for _, match := range matches {
		if len(match) > 1 {
			ipv6Addrs = append(ipv6Addrs, match[1])
		}
	}

	for _, addr := range ipv6Addrs {
		output, err := exec.Command("netsh", "interface", "ipv6", "delete", "address", iface, addr).CombinedOutput()
		if err != nil {
			log.Printf("删除接口 %s 上的 IPv6 地址 %s 时出错: %v\n", addr, iface, err)
			log.Println(decodeGBK(output))
			continue
		}
		log.Printf("已删除接口 %s 上的 IPv6 地址 %s\n", addr, iface)
	}

	output, err := exec.Command("netsh", "interface", "ipv6", "show", "route").CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "::/0") {
				output, err = exec.Command("netsh", "interface", "ipv6", "delete", "route", "::/0", iface).CombinedOutput()
				if err != nil {
					log.Println("删除 IPV6 路由时出错:")
					log.Println(decodeGBK(output))
					return
				}
				log.Printf("已删除接口 %s 上的默认 IPV6 路由\n", iface)
				break
			}
		}
	}
	output, err = exec.Command("netsh", "interface", "ipv6", "delete", "dnsservers", iface, "all").CombinedOutput()
	if err != nil {
		log.Printf("删除接口 %s 上的 DNS 服务器时出错: %v\n", iface, err)
		log.Println(decodeGBK(output))
		return
	}
	log.Printf("已删除接口 %s 上的 DNS 服务器\n", iface)

	output, err = exec.Command("netsh", "interface", "set", "interface", "name="+iface, "admin=disable").CombinedOutput()
	if err != nil {
		log.Printf("禁用接口 %s 时出错: %v\n", iface, err)
		log.Println(decodeGBK(output))
		return
	}
	log.Printf("已禁用接口 %s\n", iface)

	time.Sleep(3 * time.Second)

	output, err = exec.Command("netsh", "interface", "set", "interface", "name="+iface, "admin=enable").CombinedOutput()
	if err != nil {
		log.Printf("启用接口 %s 时出错: %v\n", iface, err)
		log.Println(decodeGBK(output))
		return
	}
	log.Printf("已启用接口 %s\n", iface)

	fmt.Printf(dhcpv6Success, iface)
	log.Printf("已成功为接口 %s 配置 DHCPv6\n", iface)
}

// Helper function to set static IP configuration
func setStaticIPConfiguration(iface string, signalChan chan os.Signal) bool {
	ip, ctrlC := getValidIPInput("设置 IP 地址", "", signalChan)
	if ctrlC {
		return true
	}
	netmask, ctrlC := getValidNetmask("", signalChan)
	if ctrlC {
		return true
	}
	gateway, ctrlC := getValidIPInput("设置网关", "", signalChan)
	if ctrlC {
		return true
	}
	dns, ctrlC := getValidIPInput("设置 DNS", "", signalChan)
	if ctrlC {
		return true
	}

	yellowColor.Println(configuringStaticIP)
	output, err := exec.Command("netsh", "interface", "ipv4", "set", "address", iface, "static", ip, netmask, gateway).CombinedOutput()
	if err != nil {
		redColor.Println("设置静态 IP 配置时出错:")
		redColor.Println(decodeGBK(output))
		return false
	}

	output, err = exec.Command("netsh", "interface", "ip", "del", "dns", "name="+iface, "all").CombinedOutput()
	if err != nil {
		redColor.Println("删除 DNS 配置时出错:")
		redColor.Println(decodeGBK(output))
		return false
	}

	output, err = exec.Command("netsh", "interface", "ipv4", "set", "dns", iface, "static", dns).CombinedOutput()
	if err != nil {
		redColor.Println("设置 DNS 时出错:")
		redColor.Println(decodeGBK(output))
		return false
	}

	fmt.Printf(staticIPSuccess, iface)
	return false //执行成功
}

func setStaticIPv6Configuration(iface string, signalChan chan os.Signal) bool {
	ipv6Address, ctrlC := getValidIPv6Input("设置 IPv6 地址", "", signalChan)
	if ctrlC {
		return true
	}
	prefix := getValidv6Input("设置子网前缀长度 (例如: 64)", []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "100", "101", "102", "103", "104", "105", "106", "107", "108", "109", "110", "111", "112", "113", "114", "115", "116", "117", "118", "119", "120", "121", "122", "123", "124", "125", "126", "127", "128"}, "无效的前缀长度，请输入 0 到 128 之间的数字。")
	gateway, ctrlC := getValidIPv6Input("设置 IPv6 网关 (例如: fe80::1)", "", signalChan)
	if ctrlC {
		return true
	}
	dnsPrimary, ctrlC := getValidIPv6Input("设置首选 IPv6 DNS", "", signalChan)
	if ctrlC {
		return true
	}
	yellowColor.Println(configuringStaticIPv6)

	output, err := exec.Command("netsh", "interface", "ipv6", "set", "address", iface, "address="+ipv6Address+"/"+prefix).CombinedOutput()
	if err != nil {
		redColor.Println("设置 IPv6 地址时出错:")
		redColor.Println(decodeGBK(output))
		return false
	}

	output, err = exec.Command("netsh", "interface", "ipv6", "show", "route").CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "::/0") {
				output, err = exec.Command("netsh", "interface", "ipv6", "delete", "route", "::/0", iface).CombinedOutput()
				if err != nil {
					log.Println("删除 IPV6 路由时出错:")
					log.Println(decodeGBK(output))
					return false
				}
				break
			}
		}
	}

	output, err = exec.Command("netsh", "interface", "ipv6", "add", "route", "::/0", iface, gateway).CombinedOutput()
	if err != nil {
		redColor.Println("设置 IPv6 路由时出错:")
		redColor.Println(decodeGBK(output))
		return false
	}
	output, err = exec.Command("netsh", "interface", "ipv6", "delete", "dnsservers", iface, "all").CombinedOutput()
	if err != nil {
		redColor.Println("删除 DNS 配置时出错:")
		redColor.Println(decodeGBK(output))
		return false
	}
	output, err = exec.Command("netsh", "interface", "ipv6", "set", "dnsservers", iface, "static", dnsPrimary, "validate=no").CombinedOutput()
	if err != nil {
		redColor.Println("设置 IPv6 DNS 时出错:")
		redColor.Println(decodeGBK(output))
		return false
	}
	fmt.Printf(staticIPSuccess, iface)
	return false //执行成功
}

func addIPAddress(iface string, signalChan chan os.Signal) bool {
	ip, ctrlC := getValidIPInput("设置 IP 地址", "", signalChan)
	if ctrlC {
		return true
	}
	netmask, ctrlC := getValidNetmask("", signalChan)
	if ctrlC {
		return true
	}
	output, err := exec.Command("netsh", "interface", "ip", "add", "address", "name="+iface, "addr="+ip, "mask="+netmask).CombinedOutput()
	if err != nil {
		redColor.Println("添加 IP 地址时出错:")
		redColor.Println(decodeGBK(output))
		return false
	}

	fmt.Printf(addIPSuccess, iface, ip)
	return false //执行成功
}
func addIPv6IPAddress(iface string, signalChan chan os.Signal) bool {
	ipv6Address, ctrlC := getValidIPv6Input("设置 IPv6 地址", "", signalChan)
	if ctrlC {
		return true
	}
	prefix := getValidv6Input("设置子网前缀长度 (例如: 64)", []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "100", "101", "102", "103", "104", "105", "106", "107", "108", "109", "110", "111", "112", "113", "114", "115", "116", "117", "118", "119", "120", "121", "122", "123", "124", "125", "126", "127", "128"}, "无效的前缀长度，请输入 0 到 128 之间的数字。")
	output, err := exec.Command("netsh", "interface", "ipv6", "add", "address", iface, "address="+ipv6Address+"/"+prefix).CombinedOutput()
	if err != nil {
		redColor.Println("添加 IPv6 地址时出错:")
		redColor.Println(decodeGBK(output))
		return false
	}

	fmt.Printf(addIPv6Success, iface, ipv6Address)
	return false //执行成功
}
func removeIPAddress(iface string, signalChan chan os.Signal) bool {
	ip, ctrlC := getValidIPInput("设置要移除的 IP 地址", "", signalChan)
	if ctrlC {
		return true
	}
	output, err := exec.Command("netsh", "interface", "ip", "delete", "address", "name="+iface, "addr="+ip).CombinedOutput()
	if err != nil {
		redColor.Println("移除 IP 地址时出错:")
		redColor.Println(decodeGBK(output))
		return false
	}
	fmt.Printf(removeIPSuccess, iface, ip)
	return false //执行成功
}
func removeIPv6IPAddress(iface string, signalChan chan os.Signal) bool {
	ipv6Address, ctrlC := getValidIPv6Input("设置要移除的 IPv6 地址", "", signalChan)
	if ctrlC {
		return true
	}
	output, err := exec.Command("netsh", "interface", "ipv6", "delete", "address", iface, ipv6Address).CombinedOutput()
	if err != nil {
		redColor.Println("移除 IPv6 地址时出错:")
		redColor.Println(decodeGBK(output))
		return false
	}
	fmt.Printf(removeIPv6Success, iface, ipv6Address)
	return false //执行成功
}

// 显示当前配置
func showCurrentConfig(interfaceName string) {
	defaultColor.Println(currentConfig)
	output, err := exec.Command("netsh", "interface", "ip", "show", "config", "name="+interfaceName).CombinedOutput()
	if err != nil {
		return
	}
	defaultColor.Println(decodeGBK(output))

	outputByte, err := exec.Command("netsh", "interface", "ipv6", "show", "address", fmt.Sprintf("interface=%s", interfaceName)).CombinedOutput()
	if err != nil {
		return
	}
	outputStr := string(outputByte)
	re := regexp.MustCompile(`(?:Address|地址)\s+([\da-fA-F:]+)`)
	matches := re.FindAllStringSubmatch(outputStr, -1)
	for _, match := range matches {
		if (len(match) > 1 && !strings.Contains(match[0], "Type")) || (len(match) > 1 && strings.Contains(match[0], "地址")) {
			match = match[:len(match)-1]
			defaultColor.Println(match)
		}
	}
	yellowColor.Print("\n按 Enter 继续...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func selectInterfaceFromList(signalChan chan os.Signal) (string, bool) {

	output, err := executeNetshCommand("interface", "show", "interface")
	if err != nil {
		return "", false
	}
	var interfaces []string
	lines := strings.Split(string(output), "\n")
	re := regexp.MustCompile(`^\s*\d+\.\s+(.*)$`)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		match := re.FindStringSubmatch(line)
		if len(match) > 1 {
			parts := strings.Fields(match[1])
			if len(parts) > 0 && parts[0] != "管理员" && parts[0] != "状态" {
				interfaces = append(interfaces, parts[0])
			}
		}
		if strings.HasPrefix(line, "名称") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				for _, iface := range parts[1:] {
					if iface != "管理员" && iface != "状态" {
						interfaces = append(interfaces, iface)

					}
				}
			}
			continue
		}
		if strings.HasPrefix(line, "----") {
			continue
		}
		if len(line) > 0 {
			parts := strings.Fields(line)
			if len(parts) > 3 {
				interfaces = append(interfaces, parts[3])
			}
		}

	}
	interfaces = interfaces[1:]
	if len(interfaces) == 0 {
		redColor.Println("没有可用的网络接口")
		return "", false
	}
	yellowColor.Println("请选择一个接口:")
	indexedInterfaces := make(map[int]string)
	for i, iface := range interfaces {
		iface, err := decodeGBK([]byte(iface))
		if err != nil {
			redColor.Printf("解码接口名称时出错: %v\n", err)
			continue
		}
		indexedInterfaces[i+1] = iface
		defaultColor.Printf("%d. %s\n", i+1, iface)
	}
	maxIndex := len(indexedInterfaces)
	// fmt.Printf("可用的接口索引 (1-%d):\n", maxIndex)

	reader := bufio.NewReader(os.Stdin)
	for {
		select {
		case <-signalChan:
			return "", true // return true  when ctrl+c
		default:

			yellowColor.Printf("\n请选择接口索引 (1-%d 或 ctrl+c 或 exit ): ", maxIndex)
			input, err := reader.ReadString('\n')
			if err != nil {
				continue // avoid panic when signal receive
			}
			input = strings.TrimSpace(input)

			if input == exitString {
				os.Exit(0)
			}
			selectedIndex, err := strconv.Atoi(input)
			if err != nil {
				redColor.Println("输入无效，请重新输入数字。")
				continue
			}

			if selectedIndex < 1 || selectedIndex > maxIndex {
				redColor.Printf("索引超出范围，请选择 1 到 %d 之间的数字。\n", maxIndex)
				continue
			}

			if _, exists := indexedInterfaces[selectedIndex]; !exists {
				redColor.Println("索引不存在，请重新输入。")
				continue
			}
			return indexedInterfaces[selectedIndex], false
		}

	}

}

// 选项处理函数
func handleOption(option string, interfaceName string, signalChan chan os.Signal) bool {
	switch option {
	case "1":
		return true // 返回到接口选择
	case "2":
		showCurrentConfig(interfaceName)
		return false
	case "41":
		setDHCPConfiguration(interfaceName)
		return false
	case "42":
		if handleCtrlC(setStaticIPConfiguration, interfaceName, signalChan) {
			return true
		}
		return false
	case "43":
		if handleCtrlC(addIPAddress, interfaceName, signalChan) {
			return true
		}
		return false
	case "44":
		if handleCtrlC(removeIPAddress, interfaceName, signalChan) {
			return true
		}
		return false
	case "61":
		setDHCPIPv6Configuration(interfaceName)
		return false
	case "62":
		if handleCtrlC(setStaticIPv6Configuration, interfaceName, signalChan) {
			return true
		}
		return false
	case "63":
		if handleCtrlC(addIPv6IPAddress, interfaceName, signalChan) {
			return true
		}
		return false
	case "64":
		if handleCtrlC(removeIPv6IPAddress, interfaceName, signalChan) {
			return true
		}
		return false
	}
	return false
}

// 处理 Ctrl+C 信号的函数
func handleCtrlC(fn func(string, chan os.Signal) bool, interfaceName string, signalChan chan os.Signal) bool {
	done := make(chan struct{}) // 通知主函数是否中断
	go func() {
		select {
		case <-signalChan:
			fmt.Println("\n返回到选项选择.")
			close(done) // 通知主函数中断
			return
		case <-done:
			return
		}
	}()

	// 执行传入的函数
	result := fn(interfaceName, signalChan)

	// 检查是否发生了中断
	select {
	case <-done:
		return true // 中断
	default:
		return result // 返回 fn 的执行结果
	}
}

func main() {
	validInterfaces := []string{"lan", "wlan", "s", exitString}
	var interfaceName string
	var adapterFound bool
	defaultColor.Println(networkToolTitle)
	defaultColor.Println(networkToolDivLine)
	var signalChan = make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT)
	defer signal.Stop(signalChan)
mainLoop:
	for {
		adapterFound = false
		for !adapterFound {
			interfaceName, _ = getValidInput("设置接口 (lan, wlan, s, 或 exit)", validInterfaces, invalidInterface, nil)
			if interfaceName == "" {
				continue
			}
			if interfaceName == "s" {
				var ctrlC1 bool
				var signalChan = make(chan os.Signal, 1)
				signal.Notify(signalChan, syscall.SIGINT)
				defer signal.Stop(signalChan)
				interfaceName, ctrlC1 = selectInterfaceFromList(signalChan)
				decodedName, err := decodeGBK([]byte(interfaceName))
				if err != nil {
					redColor.Printf("解码接口名称时出错: %v\n", err)
					continue
				}
				interfaceName = decodedName
				if ctrlC1 {
					yellowColor.Println("\n返回到接口选择.")
					continue mainLoop
				}
				if interfaceName == "" {
					continue
				}
			}
			_, err := executeNetshCommand("interface", "show", "interface", "name="+interfaceName)
			if err == nil {
				adapterFound = true
			} else {
				redColor.Printf(adapterNotFound, interfaceName)
			}
		}

		for {
			defaultColor.Println(availableOptions)
			defaultColor.Println("1. 返回到接口选择")
			defaultColor.Println("2. 查看当前配置")
			defaultColor.Println("41. 配置 IPv4(DHCP)")
			defaultColor.Println("42. 配置 IPv4(静态)")
			defaultColor.Println("43. 添加 IPv4")
			defaultColor.Println("44. 移除 IPv4")
			defaultColor.Println("61. 配置 IPv6(DHCP)")
			defaultColor.Println("62. 配置 IPv6(静态)")
			defaultColor.Println("63. 添加 IPv6")
			defaultColor.Println("64. 移除 IPv6")

			validInputs := append([]string{"1", "2", exitString}, func() []string {
				var temp []string
				for i := 41; i <= 44; i++ {
					temp = append(temp, strconv.Itoa(i))
				}
				for i := 61; i <= 64; i++ {
					temp = append(temp, strconv.Itoa(i))
				}
				return temp
			}()...)
			var signalChan = make(chan os.Signal, 1)
			signal.Notify(signalChan, syscall.SIGINT)
			defer signal.Stop(signalChan)
			option, ctrlC2 := getValidInput("\n选择一个选项 (1-2 或 41-44 或 61-64 或 ctrl+c 或 exit)", validInputs, invalidOption, signalChan)
			if ctrlC2 {
				yellowColor.Println("\n返回到接口选择.")
				continue mainLoop
			}
			if handleOption(option, interfaceName, signalChan) {
				continue mainLoop
			}
		}
	}
}
