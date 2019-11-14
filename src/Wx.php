<?php
/**
 * 微信小程序操作类
 *
 * @author limancheng<limancheng@smartfinancecloud.com>
 * @date 2019-11-11 15:10:00
 */

namespace limanc\wxMiniProgram;


class Wx
{
    /**
     * error code 说明.
     * <ul>

     *    <li>-41001: encodingAesKey 非法</li>
     *    <li>-41003: aes 解密失败</li>
     *    <li>-41004: 解密后得到的buffer非法</li>
     *    <li>-41005: base64加密失败</li>
     *    <li>-41016: base64解密失败</li>
     * </ul>
     */
    public static $OK = 0;
    public static $IllegalAesKey = -41001;
    public static $IllegalIv = -41002;
    public static $IllegalBuffer = -41003;
    public static $DecodeBase64Error = -41004;
    public static $NoAccessToken = -41005;

    public $appId;
    public $appSecret;

    /**
     * 构造函数
     */
    public function __construct($appId, $appSecret)
    {
        $this->appId = $appId;
        $this->appSecret = $appSecret;
    }

    /**
     * 获取access_token
     * */
    public function getAccessToken(){
        $url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=".$this->appId."&secret=".$this->appSecret;

        return $this->curlGet($url);
    }
    /**
     * 获取sessionKey
     * @code 登录凭证（code）
     * */
    public function getSessionKey($code){
        $url = "https://api.weixin.qq.com/sns/jscode2session?appid=".$this->appId."&secret=".$this->appSecret."&js_code=".$code."&grant_type=authorization_code";
        return $this->curlGet($url);
    }

    /**
     * 检验数据的真实性，并且获取解密后的明文.
     * @param $encryptedData string 加密的用户数据
     * @param $iv string 与用户数据一同返回的初始向量
     * @param $data string 解密后的原文
     *
     * @return int 成功0，失败返回对应的错误码
     */
    public function decryptData( $encryptedData, $iv )
    {

        if (strlen($this->sessionKey) != 24) {
            return self::$IllegalAesKey;
        }
        $aesKey=base64_decode($this->sessionKey);


        if (strlen($iv) != 24) {
            return self::$IllegalIv;
        }
        $aesIV=base64_decode($iv);

        $aesCipher=base64_decode($encryptedData);

        $result=openssl_decrypt( $aesCipher, "AES-128-CBC", $aesKey, 1, $aesIV);

        $dataObj=json_decode( $result );
        if( $dataObj  == NULL )
        {
            return self::$IllegalBuffer;
        }
        if( $dataObj->watermark->appid != $this->appid )
        {
            return self::$IllegalBuffer;
        }
        return $dataObj;
    }

    /**
     * 发送订阅消息
     * @data touser 接收者openid
     * @data template_id 订阅模板id
     * @data page 点击模板卡片后的跳转页面，仅限本小程序内的页面
     * @data data 模板内容，格式形如 { "key1": { "value": any }, "key2": { "value": any } }
     * @accessToken  是小程序全局唯一后台接口调用凭据access_token
     * */
    public function subscribeMessageSend($data){
        //获取access_token
        $accessToken = $this->getAccessToken();
        if(isset($accessToken['errcode']) && $accessToken['errcode'] !=0){
            return $accessToken;
        }
        //发送消息
        $url = "https://api.weixin.qq.com/cgi-bin/message/subscribe/send?access_token=".$accessToken['access_token'];
        $postData['touser'] = $data['touser'];
        $postData['template_id'] = $data['template_id'];
        $postData['page'] = $data['page'];
        $postData['data'] = $data['data'];

        return $this->curlPost($url, json_encode($postData));
    }

    /**
     * get 请求
     * */
    public function curlGet($url){
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($ch);
        curl_close($ch);
        $output = json_decode($output,true);
        return $output;
    }

    /**
     * post 请求
     * */
    public function curlPost($url, $data){
        //初使化init方法
        $ch = curl_init();
        //指定URL
        curl_setopt($ch, CURLOPT_URL, $url);
        //设定请求后返回结果
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        //声明使用POST方式来进行发送
        curl_setopt($ch, CURLOPT_POST, 1);
        //发送什么数据呢
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        //忽略证书
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        //忽略header头信息
        curl_setopt($ch, CURLOPT_HEADER, 0);
        //设置超时时间
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        //发送请求
        $output = curl_exec($ch);
        //关闭curl
        curl_close($ch);
        //返回数据
        return $output;
    }
}
